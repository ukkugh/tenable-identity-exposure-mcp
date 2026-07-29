"""Resource catalog for the Tenable Identity Exposure API.

Paths here were verified against a live TIE instance (v3.120.1 SaaS).
Flat resources support generic CRUD via `tie_resource_action`.
Nested resources (deviances, attacks, alerts lists, scores, widgets) live
under parent paths and are exposed through dedicated tools in server.py.
"""

from __future__ import annotations

from typing import NamedTuple

_R = frozenset({"GET"})
_RW = frozenset({"GET", "PATCH", "DELETE"})
_RC = frozenset({"GET", "POST"})
_RP = frozenset({"GET", "PATCH"})
_NONE: frozenset[str] = frozenset()


class TIEResource(NamedTuple):
    """A flat resource and the methods it actually serves.

    `collection` applies to the base path, `item` to `<path>/{id}`. An empty
    `item` means there is no per-id route at all — asking for one used to
    produce a confident 404 instead of a local refusal.
    """

    path: str
    collection: frozenset[str]
    item: frozenset[str]
    description: str

    @property
    def supports_id(self) -> bool:
        return bool(self.item)


# Method sets come from Tenable's published OpenAPI spec and were spot-checked
# with GET against a live TIE v3.120.1 SaaS tenant. Notably: /api/ad-objects/{id}
# and /api/attack-types/{id} do not exist, and /api/directories/{id} serves GET
# only -- directory writes go through /api/infrastructures/{infraId}/directories/{id}.
TIE_RESOURCES: dict[str, TIEResource] = {
    "about":                TIEResource("/api/about",                 _R,    _NONE, "Product version and build info"),
    "ad-objects":           TIEResource("/api/ad-objects",            _R,    _NONE, "AD objects; whole-collection dump, no per-id route -- use tie_search_ad_objects"),
    "application-settings": TIEResource("/api/application-settings",  _RP,   _NONE, "Global application settings"),
    "attack-type-configuration": TIEResource("/api/attack-type-configuration", _RP, _NONE, "Attack type configuration"),
    "attack-types":         TIEResource("/api/attack-types",          _R,    _NONE, "Attack (IoA) type definitions; no per-id route"),
    "categories":           TIEResource("/api/categories",            _R,    _R,    "Indicator of Exposure (IoE) categories"),
    "checkers":             TIEResource("/api/checkers",              _R,    _R,    "IoE checker definitions"),
    "cloud-statistics":     TIEResource("/api/cloud-statistics",      _R,    _NONE, "Cloud deployment statistics"),
    "dashboards":           TIEResource("/api/dashboards",            _RC,   _RW,   "Dashboard definitions"),
    "directories":          TIEResource("/api/directories",           _RC,   _R,    "Monitored AD directories; per-id is read-only"),
    "email-notifiers":      TIEResource("/api/email-notifiers",       _RC,   _RW,   "Email notification configurations"),
    "infrastructures":      TIEResource("/api/infrastructures",       _RC,   _RW,   "Monitored AD forests / infrastructures"),
    "ldap-configuration":   TIEResource("/api/ldap-configuration",    _RP,   _NONE, "LDAP bind configuration"),
    "license":              TIEResource("/api/license",               _RC,   _NONE, "License information"),
    "lockout-policy":       TIEResource("/api/lockout-policy",        _RP,   _NONE, "Account lockout policy"),
    "preferences":          TIEResource("/api/preferences",           _RP,   _NONE, "Current user preferences"),
    "profiles":             TIEResource("/api/profiles",              _RC,   _RW,   "Security profiles (scope for IoE/IoA data)"),
    "reasons":              TIEResource("/api/reasons",               _R,    _R,    "Deviance closure reasons"),
    "roles":                TIEResource("/api/roles",                 _RC,   _RW,   "Console user roles and permissions"),
    "saml-configuration":   TIEResource("/api/saml-configuration",    _RP,   _NONE, "SAML SSO configuration"),
    "syslogs":              TIEResource("/api/syslogs",               _RC,   _RW,   "Syslog forwarding configurations"),
    "users":                TIEResource("/api/users",                 _RC,   _RW,   "Console user accounts"),
}

# Nested resources exposed via dedicated tools. Documented here for discovery.
NESTED_ENDPOINTS: dict[str, str] = {
    "attacks":             "GET  /api/profiles/{profileId}/attacks   (requires resourceType + resourceValue)  -> use tie_attacks",
    "deviances (checker)": "POST /api/profiles/{profileId}/checkers/{checkerId}/deviances                     -> use tie_deviances_by_checker",
    "deviances (dir)":     "GET  /api/infrastructures/{infraId}/directories/{dirId}/deviances                 -> use tie_deviances_by_directory",
    "deviances (changed)": "GET  /api/deviances/changed   (bulk cursor-paginated stream)                      -> use tie_deviances_bulk",
    "alerts (list)":       "GET  /api/profiles/{profileId}/alerts                                             -> use tie_alerts",
    "alerts (single)":     "GET/PATCH /api/alerts/{id}                                                        -> use tie_request",
    "scores":              "GET  /api/profiles/{profileId}/scores                                             -> use tie_scores",
    "topology":            "GET  /api/profiles/{profileId}/topology  (AD trusts / relationships)             -> use tie_topology",
    "events (search)":     "POST /api/events/search  (needs profileId, directoryIds, dateStart/End)          -> use tie_search_events",
    "whoami":              "GET  /api/users/whoami   (current user + permissions)                            -> use tie_whoami",
    "widgets":             "GET/POST/PATCH/DELETE /api/dashboards/{dashboardId}/widgets[/{id}]               -> use tie_request",
    "checker-options":     "GET/POST /api/profiles/{profileId}/checkers/{checkerId}/checker-options          -> use tie_request",
    "attack-type-options": "GET/POST /api/profiles/{profileId}/attack-types/{attackTypeId}/attack-type-options -> use tie_request",
    "reasons (checker)":   "GET  /api/profiles/{profileId}/checkers/{checkerId}/reasons                       -> use tie_request",
    "ad-objects (search)": "POST /api/profiles/{profileId}/checkers/{checkerId}/ad-objects/search             -> use tie_request",
}

# Endpoints this server refuses for every method, credential-bearing ones
# included. Advertised here so the model is told once, instead of discovering
# the boundary one refusal at a time and retrying around it.
BLOCKED_ENDPOINTS: dict[str, str] = {
    "/api/api-key": "returns the console API key this server authenticates with",
    "/api/report-access-token": "returns the embedded-report access token",
    "/api/relays/linking-key": "returns the relay enrolment secret",
}


def catalog_as_text() -> str:
    lines = [
        "Flat resources (use with tie_resource_action).",
        "Methods shown are what the API actually serves: collection | item(/{id}).",
        "'-' means that level has no route, so the matching action is refused locally.\n",
    ]
    for name, r in sorted(TIE_RESOURCES.items()):
        coll = ",".join(sorted(r.collection)) or "-"
        item = ",".join(sorted(r.item)) or "-"
        lines.append(f"  {name:<22} {r.path:<32} [{coll} | {item}]  {r.description}")
    lines.append("\nNested resources (use the dedicated tools noted):\n")
    for name, doc in NESTED_ENDPOINTS.items():
        lines.append(f"  {name:<20} {doc}")
    lines.append("\nNever accessible through this server, by any method or tool:\n")
    for path, why in BLOCKED_ENDPOINTS.items():
        lines.append(f"  {path:<30} {why}")
    return "\n".join(lines)
