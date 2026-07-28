"""Shared fixtures: a recording stand-in for TIEClient."""

from __future__ import annotations

from typing import Any

import pytest

from tenable_tie_mcp import server


class FakeClient:
    """Records every call and replays canned responses.

    `responses` maps a path to the value returned for it; `default` is used for
    anything unmapped. Set `raise_on_call=True` to assert a guard fired before
    any network access was attempted.
    """

    def __init__(
        self,
        responses: dict[str, Any] | None = None,
        default: Any = None,
        pages: dict[str, list[Any]] | None = None,
    ) -> None:
        self.responses = responses or {}
        self.default = default if default is not None else []
        # Paths in `pages` answer with a different value per successive call,
        # so pagination loops can be exercised.
        self.pages = {k: list(v) for k, v in (pages or {}).items()}
        self.calls: list[dict[str, Any]] = []

    async def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> Any:
        self.calls.append({"method": method.upper(), "path": path, "params": params, "json": json})
        queued = self.pages.get(path)
        if queued:
            return queued.pop(0)
        return self.responses.get(path, self.default)

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


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> FakeClient:
    client = FakeClient()
    monkeypatch.setattr(server, "_client", client)
    return client
