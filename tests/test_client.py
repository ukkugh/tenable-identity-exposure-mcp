"""Tests for TIEConfig / TIEClient."""

from __future__ import annotations

import httpx
import pytest

from tenable_tie_mcp.client import TIEApiError, TIEClient, TIEConfig


def _config(**kw: object) -> TIEConfig:
    kw.setdefault("base_url", "https://tie.example")
    kw.setdefault("api_key", "SENTINEL")
    return TIEConfig(**kw)  # type: ignore[arg-type]


class TestVerifySslFromEnvironment:
    def test_env_false_disables_verification(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TIE_VERIFY_SSL", "false")
        assert _config().verify_ssl is False

    @pytest.mark.parametrize("value", ["false", "FALSE", "0", "no"])
    def test_falsey_env_values_disable_verification(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TIE_VERIFY_SSL", value)
        assert _config().verify_ssl is False

    def test_env_absent_defaults_to_verifying(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TIE_VERIFY_SSL", raising=False)
        assert _config().verify_ssl is True

    def test_explicit_argument_overrides_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TIE_VERIFY_SSL", "false")
        assert _config(verify_ssl=True).verify_ssl is True


class TestAbsoluteUrlRejection:
    """The API key is a client-level header, so httpx would attach it to ANY
    absolute URL passed as `path`, exfiltrating the credential."""

    @pytest.mark.parametrize(
        "path",
        [
            "https://attacker.example/collect",
            "http://attacker.example/collect",
            "//attacker.example/collect",
            "HTTPS://attacker.example/collect",
        ],
    )
    async def test_absolute_path_is_refused(self, path: str) -> None:
        client = TIEClient(_config())
        try:
            with pytest.raises(TIEApiError) as exc:
                await client.request("GET", path)
            assert "absolute" in str(exc.value).lower()
        finally:
            await client.close()

    @pytest.mark.parametrize(
        "path",
        [
            "/api/dashboards/../users/5",
            "/api/./users",
            "api/../../etc/passwd",
            "/api/dashboards/%2e%2e/users",
        ],
    )
    async def test_dot_segments_are_refused(self, path: str) -> None:
        """httpx removes dot segments before sending, so any caller path that
        would be rewritten must be rejected rather than silently redirected."""
        client = TIEClient(_config())
        try:
            with pytest.raises(TIEApiError) as exc:
                await client.request("GET", path)
            assert "traversal" in str(exc.value).lower()
        finally:
            await client.close()

    async def test_relative_path_is_normalised_with_leading_slash(self) -> None:
        client = TIEClient(_config())
        try:
            assert client._normalise_path("api/about") == "/api/about"
            assert client._normalise_path("/api/about") == "/api/about"
        finally:
            await client.close()


class TestTransportErrors:
    """Every tool catches only TIEApiError. Transport failures used to sail past
    those handlers, and a timeout surfaced as a message with no content at all
    because httpx.ConnectTimeout stringifies to the empty string."""

    async def _request_with(self, exc: Exception) -> TIEApiError:
        def handler(request: httpx.Request) -> httpx.Response:
            raise exc

        client = TIEClient(_config())
        client._http = httpx.AsyncClient(
            base_url="https://tie.example",
            headers={"X-API-Key": "SENTINEL"},
            transport=httpx.MockTransport(handler),
        )
        try:
            with pytest.raises(TIEApiError) as caught:
                await client.request("GET", "/api/about")
            return caught.value
        finally:
            await client.close()

    async def test_connect_error_becomes_a_tie_api_error(self) -> None:
        err = await self._request_with(httpx.ConnectError("nodename nor servname provided"))

        assert err.status == 0
        assert "nodename" in str(err)

    async def test_timeout_still_names_the_failure(self) -> None:
        """ConnectTimeout carries an empty message; the class name has to
        survive or the operator gets a bare 'Error executing tool'."""
        err = await self._request_with(httpx.ConnectTimeout(""))

        assert "ConnectTimeout" in str(err)

    async def test_certificate_failure_points_at_the_setting(self) -> None:
        err = await self._request_with(
            httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate")
        )

        assert "TIE_VERIFY_SSL" in str(err)
