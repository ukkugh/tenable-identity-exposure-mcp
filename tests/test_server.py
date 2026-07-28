"""Tests for the MCP tool layer and the process entry point."""

from __future__ import annotations

import subprocess
import sys
from typing import Any

import pytest

from tenable_tie_mcp import server

from .conftest import FakeClient


class TestDeviancesBulkEnvelope:
    """GET /api/deviances/changed returns a HAL envelope, not a bare array.
    Misreading it turns "hundreds of findings" into a silent "count: 0"."""

    async def test_hal_envelope_records_are_returned(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        page = {
            "_embedded": {
                "deviance": [
                    {"id": 1, "checkerId": 7, "profileId": 1},
                    {"id": 2, "checkerId": 8, "profileId": 1},
                ]
            }
        }
        client = FakeClient(responses={"/api/deviances/changed": page})
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_deviances_bulk(batch_size=200, max_batches=2)

        assert result["count"] == 2
        assert [d["id"] for d in result["deviances"]] == [1, 2]

    async def test_bare_array_response_is_still_supported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        page = [{"id": 1, "checkerId": 7, "profileId": 1}]
        client = FakeClient(responses={"/api/deviances/changed": page})
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_deviances_bulk(batch_size=200, max_batches=2)

        assert result["count"] == 1

    async def test_unexpected_shape_is_reported_not_silently_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = FakeClient(responses={"/api/deviances/changed": {"unexpected": True}})
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_deviances_bulk()

        assert "error" in result

    async def test_profile_filter_applies_to_embedded_records(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        page = {
            "_embedded": {
                "deviance": [
                    {"id": 1, "profileId": 1},
                    {"id": 2, "profileId": 2},
                ]
            }
        }
        client = FakeClient(responses={"/api/deviances/changed": page})
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_deviances_bulk(profile_id=2)

        assert result["count"] == 1
        assert result["deviances"][0]["id"] == 2


class TestReadOnlyMode:
    """Writes are refused by default; the LLM must not be able to mutate a
    security console because a prompt told it to."""

    @pytest.fixture(autouse=True)
    def _default_read_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_read_only", True)

    @pytest.mark.parametrize("action", ["create", "update", "delete"])
    async def test_resource_action_writes_refused(
        self, action: str, fake_client: FakeClient
    ) -> None:
        result = await server.tie_resource_action(
            resource="dashboards", action=action, id=1, body={}
        )

        assert "error" in result
        assert "read-only" in result["error"].lower()
        assert fake_client.calls == []

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    async def test_request_writes_refused(self, method: str, fake_client: FakeClient) -> None:
        result = await server.tie_request(method=method, path="/api/dashboards")  # type: ignore[arg-type]

        assert "error" in result
        assert "read-only" in result["error"].lower()
        assert fake_client.calls == []

    async def test_reads_still_work(self, fake_client: FakeClient) -> None:
        await server.tie_resource_action(resource="dashboards", action="list")
        await server.tie_request(method="GET", path="/api/about")

        assert [c["method"] for c in fake_client.calls] == ["GET", "GET"]


class TestProtectedResources:
    """Some resources stay unwritable even when writes are enabled: rotating the
    API key kills the running server, and SSO/user/role changes are not the
    LLM's business."""

    @pytest.fixture(autouse=True)
    def _writes_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_read_only", False)

    @pytest.mark.parametrize(
        "resource",
        ["api-key", "users", "roles", "saml-configuration", "ldap-configuration"],
    )
    async def test_protected_resource_write_refused(
        self, resource: str, fake_client: FakeClient
    ) -> None:
        result = await server.tie_resource_action(resource=resource, action="create", body={})

        assert "error" in result
        assert "protected" in result["error"].lower()
        assert fake_client.calls == []

    async def test_protected_path_refused_via_raw_request(self, fake_client: FakeClient) -> None:
        result = await server.tie_request(method="POST", path="/api/api-key")

        assert "error" in result
        assert "protected" in result["error"].lower()
        assert fake_client.calls == []

    @pytest.mark.parametrize(
        "path",
        [
            # A query string or fragment must not change which endpoint this is.
            "/api/users?x=1",
            "/api/users#frag",
            "/api/api-key?",
            # httpx removes dot segments before writing the request line, so a
            # guard that matches the raw string disagrees with what is sent.
            "/api/dashboards/../users/5",
            "/api/dashboards/../../api/api-key",
            "/api/./users",
            # Spellings a router may still resolve to the protected resource.
            "/api//users",
            "/API/users",
            "/api/users/",
            "/api/users%2f1",
            "/api/dashboards/%2e%2e/users",
        ],
    )
    async def test_protected_path_spellings_refused(
        self, path: str, fake_client: FakeClient
    ) -> None:
        result = await server.tie_request(method="DELETE", path=path)

        assert "error" in result, f"{path} was not refused"
        assert fake_client.calls == [], f"{path} reached the client"

    @pytest.mark.parametrize("bad_id", ["../users/5", "../../api/api-key", "1/../users", "a b"])
    async def test_id_cannot_escape_its_resource(
        self, bad_id: str, fake_client: FakeClient
    ) -> None:
        """`id` is interpolated into the path, so a whitelisted resource name
        must not be a route to an arbitrary endpoint."""
        result = await server.tie_resource_action(
            resource="dashboards", action="delete", id=bad_id
        )

        assert "error" in result, f"{bad_id!r} was not refused"
        assert fake_client.calls == [], f"{bad_id!r} reached the client"

    async def test_wellformed_string_id_still_works(self, fake_client: FakeClient) -> None:
        await server.tie_resource_action(resource="dashboards", action="delete", id="abc-1")

        assert fake_client.calls[0]["path"] == "/api/dashboards/abc-1"

    async def test_protected_resource_read_still_allowed(self, fake_client: FakeClient) -> None:
        await server.tie_resource_action(resource="users", action="list")

        assert [c["method"] for c in fake_client.calls] == ["GET"]

    async def test_unprotected_write_allowed_when_writes_enabled(
        self, fake_client: FakeClient
    ) -> None:
        await server.tie_resource_action(resource="dashboards", action="create", body={"a": 1})

        assert fake_client.calls[0]["method"] == "POST"


class TestSearchEndpointsAreReads:
    """TIE models several searches as POST. Read-only mode must not block the
    routes catalog.py tells the model to use."""

    @pytest.fixture(autouse=True)
    def _read_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_read_only", True)

    @pytest.mark.parametrize(
        "path",
        [
            "/api/events/search",
            "/api/profiles/1/checkers/7/ad-objects/search",
            "/api/profiles/1/checkers/7/deviances",
        ],
    )
    async def test_search_post_allowed_in_read_only(
        self, path: str, fake_client: FakeClient
    ) -> None:
        await server.tie_request(method="POST", path=path, body={"expression": {}})

        assert fake_client.calls[0]["method"] == "POST"

    async def test_non_search_post_still_refused(self, fake_client: FakeClient) -> None:
        result = await server.tie_request(method="POST", path="/api/dashboards")

        assert "error" in result
        assert fake_client.calls == []

    async def test_search_suffix_on_another_endpoint_is_not_a_loophole(
        self, fake_client: FakeClient
    ) -> None:
        result = await server.tie_request(method="POST", path="/api/dashboards/search")

        assert "error" in result
        assert fake_client.calls == []


class TestModuleDefaults:
    def test_read_only_is_the_module_default(self) -> None:
        """Asserted in a clean interpreter: every other test monkeypatches this
        global, so flipping the shipped default would otherwise go unnoticed."""
        out = subprocess.run(
            [
                sys.executable,
                "-c",
                "from tenable_tie_mcp import server; print(server._read_only)",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        assert out.stdout.strip() == "True"


class TestDeviancesBulkPagination:
    async def test_multiple_pages_are_accumulated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        full = {"_embedded": {"deviance": [{"id": i, "profileId": 1} for i in range(1, 3)]}}
        tail = {"_embedded": {"deviance": [{"id": 3, "profileId": 1}]}}
        client = FakeClient(pages={"/api/deviances/changed": [full, tail]})
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_deviances_bulk(batch_size=2, max_batches=5)

        assert [d["id"] for d in result["deviances"]] == [1, 2, 3]
        # Second call must resume from the highest id seen, not restart.
        assert client.calls[1]["params"]["lastIdentifierSeen"] == 2

    async def test_resolved_filter_uses_the_documented_enum(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The API validates `resolved` against ["0", "1"]; sending "false"
        makes the whole call fail with HTTP 400 INVALID_PAYLOAD_FORMAT."""
        client = FakeClient(responses={"/api/deviances/changed": []})
        monkeypatch.setattr(server, "_client", client)

        await server.tie_deviances_bulk(resolved=False)

        assert client.calls[0]["params"]["resolved"] == "0"

    async def test_resolved_true_omits_the_filter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = FakeClient(responses={"/api/deviances/changed": []})
        monkeypatch.setattr(server, "_client", client)

        await server.tie_deviances_bulk(resolved=True)

        assert "resolved" not in client.calls[0]["params"]

    async def test_truncation_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        full = {"_embedded": {"deviance": [{"id": 1, "profileId": 1}]}}
        client = FakeClient(pages={"/api/deviances/changed": [full, full, full]})
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_deviances_bulk(batch_size=1, max_batches=2)

        assert "note" in result


class TestEntryPoint:
    """The network transports were never reachable: FastMCP.run() takes no
    host/port, so --transport sse/http raised TypeError before binding."""

    @pytest.fixture
    def recorded_run(self, monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
        calls: list[dict[str, Any]] = []

        def fake_run(*args: Any, **kwargs: Any) -> None:
            calls.append({"args": args, "kwargs": kwargs})

        monkeypatch.setattr(server.mcp, "run", fake_run)
        return calls

    def _argv(self, monkeypatch: pytest.MonkeyPatch, *extra: str) -> None:
        monkeypatch.setattr(
            "sys.argv",
            ["tenable-tie-mcp", "--tie-url", "https://tie.example", "--tie-api-key", "k", *extra],
        )

    @pytest.mark.parametrize(
        ("flag", "expected"),
        [("sse", "sse"), ("http", "streamable-http")],
    )
    def test_network_transport_starts(
        self,
        flag: str,
        expected: str,
        recorded_run: list[dict[str, Any]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._argv(monkeypatch, "--transport", flag, "--host", "1.2.3.4", "--port", "9999")

        server.main()

        assert recorded_run[0]["kwargs"] == {"transport": expected}
        assert server.mcp.settings.host == "1.2.3.4"
        assert server.mcp.settings.port == 9999

    def test_stdio_is_the_default(
        self, recorded_run: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._argv(monkeypatch)

        server.main()

        assert recorded_run[0]["kwargs"] == {"transport": "stdio"}

    def test_network_transports_bind_loopback_by_default(
        self, recorded_run: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Binding 0.0.0.0 publishes an unauthenticated console proxy."""
        monkeypatch.setattr(server.mcp.settings, "host", "0.0.0.0")
        self._argv(monkeypatch, "--transport", "sse")

        server.main()

        assert server.mcp.settings.host == "127.0.0.1"

    def test_explicit_host_is_honoured(
        self, recorded_run: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._argv(monkeypatch, "--transport", "sse", "--host", "0.0.0.0")

        server.main()

        assert server.mcp.settings.host == "0.0.0.0"

    def test_verify_ssl_env_reaches_the_client(
        self, recorded_run: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() must not pass a concrete bool, or TIE_VERIFY_SSL stays inert
        on the only path that actually builds the client."""
        monkeypatch.setenv("TIE_VERIFY_SSL", "false")
        self._argv(monkeypatch)

        server.main()

        assert server._client is not None
        assert server._client.config.verify_ssl is False

    def test_no_verify_ssl_flag_overrides_env(
        self, recorded_run: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TIE_VERIFY_SSL", raising=False)
        self._argv(monkeypatch, "--no-verify-ssl")

        server.main()

        assert server._client is not None
        assert server._client.config.verify_ssl is False

    def test_writes_are_disabled_unless_requested(
        self, recorded_run: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(server, "_read_only", False)
        self._argv(monkeypatch)

        server.main()

        assert server._read_only is True

    def test_allow_writes_flag_enables_writes(
        self, recorded_run: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(server, "_read_only", True)
        self._argv(monkeypatch, "--allow-writes")

        server.main()

        assert server._read_only is False

    def test_allow_writes_env_enables_writes(
        self, recorded_run: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(server, "_read_only", True)
        monkeypatch.setenv("TIE_ALLOW_WRITES", "true")
        self._argv(monkeypatch)

        server.main()

        assert server._read_only is False
