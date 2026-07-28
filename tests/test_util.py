"""Tests for the time-window and payload helpers."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest

from tenable_tie_mcp.util import parse_iso, render_description


@pytest.fixture
def seoul_timezone(monkeypatch: pytest.MonkeyPatch):
    """Run the test body as if the host were in KST (UTC+9)."""
    monkeypatch.setenv("TZ", "Asia/Seoul")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


class TestParseIso:
    def test_offset_less_timestamp_is_utc_not_host_local(self, seoul_timezone: None) -> None:
        """Tool docstrings document these parameters as UTC; a KST host must not
        shift the instant by 9 hours."""
        assert parse_iso("2026-07-28T00:00:00") == datetime(
            2026, 7, 28, 0, 0, tzinfo=UTC
        )

    def test_z_suffix_is_utc(self, seoul_timezone: None) -> None:
        assert parse_iso("2026-07-28T00:00:00.000Z") == datetime(
            2026, 7, 28, 0, 0, tzinfo=UTC
        )

    def test_explicit_offset_is_honoured(self, seoul_timezone: None) -> None:
        assert parse_iso("2026-07-28T09:00:00+09:00") == datetime(
            2026, 7, 28, 0, 0, tzinfo=UTC
        )


class TestRenderDescription:
    def test_null_attributes_does_not_raise(self) -> None:
        deviance = {
            "description": {"template": "The GPO <%= GpoPath %> is unlinked"},
            "attributes": None,
        }
        assert render_description(deviance) == "The GPO <%= GpoPath %> is unlinked"

    def test_placeholders_are_substituted(self) -> None:
        deviance = {
            "description": {"template": "The GPO <%= GpoPath %> is unlinked"},
            "attributes": [{"name": "GpoPath", "value": "\\\\corp\\SYSVOL\\x"}],
        }
        assert render_description(deviance) == "The GPO \\\\corp\\SYSVOL\\x is unlinked"
