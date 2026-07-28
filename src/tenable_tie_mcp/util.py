"""Helpers: UTC time windows, deviance description rendering, response slimming."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

# TIE templates embed attribute placeholders like "<%= GpoPath %>".
_PLACEHOLDER = re.compile(r"<%=\s*(\w+)\s*%>")

# Attribute values longer than this are dropped unless verbose=True. The giant
# ones (AccountSidList, AccountList, member dumps) are what blow the token budget.
_VALUE_LIMIT = 200


def iso_utc(dt: datetime) -> str:
    """Format an aware datetime as TIE-style UTC ISO 8601 with milliseconds + Z."""
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_iso(value: str) -> datetime:
    """Parse an ISO 8601 string (accepting a trailing Z) to an aware UTC datetime.

    Values without an offset are treated as UTC, matching what the tool
    docstrings promise. Without this, `.astimezone()` would read them as host
    local time and skew the window by the machine's UTC offset.
    """
    # fromisoformat has understood a trailing "Z" since Python 3.11, which the
    # project requires.
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def resolve_window(
    hours: float | None = None,
    date_start: str | None = None,
    date_end: str | None = None,
    default_hours: float = 24.0,
) -> tuple[datetime, datetime]:
    """Resolve a UTC time window.

    Explicit date_start/date_end win; otherwise the window is the last `hours`
    (or `default_hours`) ending now. All times are UTC-aware.
    """
    now = datetime.now(UTC)
    end = parse_iso(date_end) if date_end else now
    if date_start:
        start = parse_iso(date_start)
    else:
        span = hours if hours is not None else default_hours
        start = end - timedelta(hours=span)
    return start, end


def render_description(obj: dict[str, Any]) -> str | None:
    """Render a deviance's description template by substituting its attributes.

    Turns {"template": "The GPO <%= GpoPath %> is unlinked", ...} plus
    attributes [{"name": "GpoPath", "value": "..."}] into a single string.
    """
    desc = obj.get("description")
    if not isinstance(desc, dict):
        return None
    template = desc.get("template")
    if not isinstance(template, str):
        return None
    attrs = {
        a.get("name"): a.get("value")
        for a in (obj.get("attributes") or [])
        if isinstance(a, dict)
    }
    return _PLACEHOLDER.sub(lambda m: str(attrs.get(m.group(1), m.group(0))), template)


def _slim_attributes(items: list[Any]) -> list[Any]:
    out = []
    for a in items:
        if not isinstance(a, dict):
            out.append(a)
            continue
        value = a.get("value")
        if isinstance(value, str) and len(value) > _VALUE_LIMIT:
            value = f"<{len(value)} chars omitted; pass verbose=true for full value>"
        out.append({"name": a.get("name"), "value": value})
    return out


def slim_object(obj: Any, verbose: bool = False) -> Any:
    """Slim a deviance / AD-object: render its description and truncate huge
    attribute values. Returns the object unchanged when verbose=True.
    """
    if verbose or not isinstance(obj, dict):
        return obj
    out = dict(obj)
    rendered = render_description(out)
    if rendered is not None:
        out["description"] = rendered
    for key in ("attributes", "objectAttributes"):
        if isinstance(out.get(key), list):
            out[key] = _slim_attributes(out[key])
    return out


def slim_list(data: Any, verbose: bool = False) -> Any:
    """Apply slim_object across a list (or a {_embedded: {...: [...]}} envelope)."""
    if verbose:
        return data
    if isinstance(data, list):
        return [slim_object(o, verbose) for o in data]
    if isinstance(data, dict) and "_embedded" in data:
        emb = data["_embedded"]
        if isinstance(emb, dict):
            for k, v in emb.items():
                if isinstance(v, list):
                    emb[k] = [slim_object(o, verbose) for o in v]
    return data
