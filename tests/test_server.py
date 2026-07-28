"""Tests for the MCP tool layer and the process entry point."""

from __future__ import annotations

import subprocess
import sys
from typing import Any

import pytest

from tenable_tie_mcp import server

from .conftest import FakeClient


def client_call(client: FakeClient, index: int) -> tuple[str, str]:
    call = client.calls[index]
    return call["method"], call["path"]


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


class TestUnsupportedActionsAreRefusedLocally:
    """The catalogue claimed get-by-id for routes that do not exist. Verified
    against a live TIE v3.120.1 tenant and the published OpenAPI spec."""

    @pytest.fixture(autouse=True)
    def _writes_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_read_only", False)

    @pytest.mark.parametrize("resource", ["ad-objects", "attack-types"])
    async def test_get_by_id_refused_where_no_item_route_exists(
        self, resource: str, fake_client: FakeClient
    ) -> None:
        result = await server.tie_resource_action(resource=resource, action="get", id=1)

        assert "error" in result
        assert fake_client.calls == []

    @pytest.mark.parametrize("action", ["update", "delete"])
    async def test_directories_item_is_read_only(
        self, action: str, fake_client: FakeClient
    ) -> None:
        """/api/directories/{id} serves GET only; writes go through
        /api/infrastructures/{i}/directories/{id}."""
        result = await server.tie_resource_action(resource="directories", action=action, id=6)

        assert "error" in result
        assert fake_client.calls == []

    async def test_directories_get_by_id_still_works(self, fake_client: FakeClient) -> None:
        await server.tie_resource_action(resource="directories", action="get", id=6)

        assert client_call(fake_client, 0) == ("GET", "/api/directories/6")

    async def test_create_refused_on_read_only_collection(
        self, fake_client: FakeClient
    ) -> None:
        result = await server.tie_resource_action(resource="categories", action="create", body={})

        assert "error" in result
        assert fake_client.calls == []

    async def test_singleton_update_patches_the_collection_path(
        self, fake_client: FakeClient
    ) -> None:
        await server.tie_resource_action(resource="preferences", action="update", body={"a": 1})

        assert client_call(fake_client, 0) == ("PATCH", "/api/preferences")

    async def test_supported_item_write_is_dispatched(self, fake_client: FakeClient) -> None:
        await server.tie_resource_action(resource="dashboards", action="delete", id=3)

        assert client_call(fake_client, 0) == ("DELETE", "/api/dashboards/3")


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


class TestRecentActivityBudget:
    """max_items is documented as a cap per category, but the IoA branch applied
    it per directory, so a four-domain forest could return 4x the stated cap
    with nothing in `notes` to say so."""

    def _tenant(self, directories: int, attacks_each: int) -> FakeClient:
        dirs = [{"id": 100 + i} for i in range(directories)]
        responses: dict[str, Any] = {"/api/directories": dirs}
        for d in dirs:
            responses["/api/profiles/1/attacks"] = [
                {"id": n, "date": f"2026-07-28T0{n % 10}:00:00.000Z", "directoryId": d["id"]}
                for n in range(attacks_each)
            ]
        responses["/api/profiles/1/alerts"] = []
        return FakeClient(responses=responses)

    async def test_ioa_cap_is_global_not_per_directory(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._tenant(directories=4, attacks_each=5)
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_recent_activity(hours=1, max_items=5)

        assert result["counts"]["ioa"] <= 5

    async def test_ioa_truncation_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = self._tenant(directories=4, attacks_each=5)
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_recent_activity(hours=1, max_items=5)

        assert any("IoA" in n for n in result["notes"])


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


def _ad_object(oid: int, cn: str, *, directory_id: int = 6, klass: str = "user",
               extra: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "id": oid,
        "directoryId": directory_id,
        "type": "LDAP",
        "objectId": f"{directory_id}:{oid:08x}",
        "objectAttributes": [
            {"name": "cn", "value": f'"{cn}"', "valueType": "string"},
            {"name": "objectclass", "value": f'["top","{klass}"]', "valueType": "array/string"},
            {"name": "distinguishedname", "value": f'"CN={cn},DC=corp,DC=local"',
             "valueType": "string"},
            *(extra or []),
        ],
    }


def _ad_page(objects: list[dict[str, Any]], *, more: bool = False) -> dict[str, Any]:
    links = {"next": "https://tie.example/api/ad-objects?lastIdentifierSeen=1"} if more else {}
    return {"_embedded": {"ad-objects": objects}, "_links": links}


class TestSearchAdObjects:
    """GET /api/ad-objects has no server-side search: search/page/perPage are
    rejected with HTTP 400, and an unfiltered call returns the whole directory."""

    async def test_only_supported_query_params_are_sent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = FakeClient(responses={"/api/ad-objects": _ad_page([])})
        monkeypatch.setattr(server, "_client", client)

        await server.tie_search_ad_objects(query="admin")

        sent = set(client.calls[0]["params"] or {})
        assert not sent & {"search", "page", "perPage", "directoryId", "type", "limit"}
        assert sent <= {"batchSize", "lastIdentifierSeen", "timestamp"}

    async def test_matches_are_found_in_the_plural_envelope(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        page = _ad_page([_ad_object(1, "Administrator"), _ad_object(2, "guest")])
        client = FakeClient(responses={"/api/ad-objects": page})
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_search_ad_objects(query="admin")

        assert result["matched"] == 1
        assert result["objects"][0]["id"] == 1

    async def test_query_is_case_insensitive_and_matches_dn(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        page = _ad_page([_ad_object(1, "svc-backup")])
        client = FakeClient(responses={"/api/ad-objects": page})
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_search_ad_objects(query="DC=CORP")

        assert result["matched"] == 1

    async def test_bulk_attribute_blobs_do_not_produce_matches(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Searching every attribute would match on ACL blobs, not on names."""
        noisy = _ad_object(
            1, "unrelated",
            extra=[{"name": "ntsecuritydescriptor", "value": '"O:S-1-5-32-544 needle"',
                    "valueType": "string"}],
        )
        client = FakeClient(responses={"/api/ad-objects": _ad_page([noisy])})
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_search_ad_objects(query="needle")

        assert result["matched"] == 0

    async def test_directory_and_class_filters_apply_client_side(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        page = _ad_page([
            _ad_object(1, "admin-a", directory_id=6, klass="user"),
            _ad_object(2, "admin-b", directory_id=7, klass="user"),
            _ad_object(3, "admin-c", directory_id=6, klass="computer"),
        ])
        client = FakeClient(responses={"/api/ad-objects": page})
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_search_ad_objects(
            query="admin", directory_id=6, object_class="user"
        )

        assert [o["id"] for o in result["objects"]] == [1]

    async def test_cursor_walks_pages(self, monkeypatch: pytest.MonkeyPatch) -> None:
        first = _ad_page([_ad_object(i, f"admin{i}") for i in range(1, 4)], more=True)
        second = _ad_page([_ad_object(9, "admin9")])
        client = FakeClient(pages={"/api/ad-objects": [first, second]})
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_search_ad_objects(query="admin", max_scanned=6)

        assert result["scanned"] == 4
        assert client.calls[1]["params"]["lastIdentifierSeen"] == 3

    async def test_result_cap_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        page = _ad_page([_ad_object(i, f"admin{i}") for i in range(1, 6)])
        client = FakeClient(responses={"/api/ad-objects": page})
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_search_ad_objects(query="admin", max_results=2)

        assert len(result["objects"]) == 2
        assert result["truncated"] is True

    async def test_oversized_attributes_are_slimmed_unless_verbose(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        blob = {"name": "ntsecuritydescriptor", "value": "x" * 900, "valueType": "string"}
        page = _ad_page([_ad_object(1, "admin", extra=[blob])])
        client = FakeClient(responses={"/api/ad-objects": page})
        monkeypatch.setattr(server, "_client", client)

        slim = await server.tie_search_ad_objects(query="admin")
        values = [a["value"] for a in slim["objects"][0]["objectAttributes"]]
        assert not any(len(str(v)) > 300 for v in values)

        client.pages.clear()
        full = await server.tie_search_ad_objects(query="admin", verbose=True)
        assert any(len(str(a["value"])) == 900 for a in full["objects"][0]["objectAttributes"])

    async def test_unexpected_shape_is_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = FakeClient(responses={"/api/ad-objects": {"unexpected": True}})
        monkeypatch.setattr(server, "_client", client)

        result = await server.tie_search_ad_objects(query="admin")

        assert "error" in result


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
