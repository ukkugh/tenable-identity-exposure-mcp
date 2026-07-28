"""HTTP client wrapper for the Tenable Identity Exposure REST API."""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx
import structlog

log = structlog.get_logger(__name__)


class TIEConfigError(ValueError):
    pass


class TIEApiError(RuntimeError):
    def __init__(self, status: int, method: str, path: str, body: str) -> None:
        self.status = status
        super().__init__(f"TIE API {method} {path} -> HTTP {status}: {body}")


_FALSEY = {"false", "0", "no", "off"}


class TIEConfig:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        verify_ssl: bool | None = None,
        timeout: float = 30.0,
        env_prefix: str = "TIE_",
    ) -> None:
        pfx = env_prefix
        self.base_url = (base_url or os.environ.get(f"{pfx}URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get(f"{pfx}API_KEY", "")
        self.verify_ssl = verify_ssl if verify_ssl is not None else (
            os.environ.get(f"{pfx}VERIFY_SSL", "true").strip().lower() not in _FALSEY
        )
        self.timeout = timeout

        if not self.base_url:
            raise TIEConfigError(f"TIE base URL not set. Provide base_url or set {pfx}URL.")
        if not self.api_key:
            raise TIEConfigError(f"TIE API key not set. Provide api_key or set {pfx}API_KEY.")


class TIEClient:
    def __init__(self, config: TIEConfig) -> None:
        self.config = config
        self._http = httpx.AsyncClient(
            base_url=config.base_url,
            headers={
                "X-API-Key": config.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            verify=config.verify_ssl,
            timeout=config.timeout,
        )

    @staticmethod
    def _normalise_path(path: str) -> str:
        """Return `path` as a server-relative path.

        httpx uses an absolute URL verbatim and ignores `base_url`, while still
        attaching the client-level `X-API-Key` header — so an unchecked `path`
        would send the TIE credential to any host the caller names.
        """
        parts = urlsplit(path)
        if parts.scheme or parts.netloc:
            raise ValueError(
                "absolute URLs are not allowed; pass a server-relative path such as /api/about"
            )
        # httpx strips dot segments before writing the request line, so a path
        # containing them would reach an endpoint different from the one any
        # caller-side check inspected. Refuse instead of silently rewriting.
        if any(seg in (".", "..") for seg in unquote(parts.path).split("/")):
            raise ValueError("path traversal segments ('.' and '..') are not allowed")
        return "/" + path.lstrip("/")

    async def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> Any:
        method = method.upper()
        try:
            path = self._normalise_path(path)
        except ValueError as exc:
            raise TIEApiError(0, method, path, str(exc)) from exc
        log.debug("tie_request", method=method, path=path, params=params)

        try:
            resp = await self._http.request(method, path, params=params, json=json)
        except httpx.HTTPError as exc:
            # Every tool catches TIEApiError and nothing else, so transport
            # failures would otherwise escape as a bare MCP error. Some of them
            # (ConnectTimeout) stringify to nothing at all, which is why the
            # exception class name is kept.
            detail = str(exc).strip()
            hint = ""
            if "CERTIFICATE_VERIFY_FAILED" in detail or "SSLError" in type(exc).__name__:
                hint = (
                    " -- if this is an on-premises appliance with an internal CA, set "
                    "TIE_VERIFY_SSL=false or pass --no-verify-ssl"
                )
            raise TIEApiError(
                0, method, path, f"{type(exc).__name__}: {detail or '(no detail)'}{hint}"
            ) from exc

        if not resp.is_success:
            raise TIEApiError(resp.status_code, method, path, resp.text[:500])

        if resp.status_code == 204 or not resp.content:
            return {"status": "ok"}

        ctype = resp.headers.get("content-type", "")
        if "json" in ctype:
            return resp.json()
        # Some endpoints (e.g. /api/metrics) return non-JSON payloads.
        try:
            return resp.json()
        except ValueError:
            return {"content_type": ctype, "text": resp.text}

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params=params)

    async def post(self, path: str, json: dict[str, Any] | None = None) -> Any:
        return await self.request("POST", path, json=json)

    async def patch(self, path: str, json: dict[str, Any] | None = None) -> Any:
        return await self.request("PATCH", path, json=json)

    async def put(self, path: str, json: dict[str, Any] | None = None) -> Any:
        return await self.request("PUT", path, json=json)

    async def delete(self, path: str) -> Any:
        return await self.request("DELETE", path)

    async def close(self) -> None:
        await self._http.aclose()
