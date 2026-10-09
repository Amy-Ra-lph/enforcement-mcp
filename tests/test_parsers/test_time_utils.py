"""Tests for time_utils parser."""

import pytest

from enforcement_mcp.parsers.time_utils import parse_time_spec


class TestParseTimeSpec:
    def test_hours(self):
        result = parse_time_spec("1h")
        assert result
        assert "/" in result  # MM/DD/YYYY format

    def test_minutes(self):
        result = parse_time_spec("30m")
        assert result

    def test_days(self):
        result = parse_time_spec("7d")
        assert result

    def test_seconds(self):
        result = parse_time_spec("300s")
        assert result

    def test_recent_keyword(self):
        assert parse_time_spec("recent") == "recent"

    def test_today_keyword(self):
        assert parse_time_spec("today") == "today"

    def test_yesterday_keyword(self):
        assert parse_time_spec("yesterday") == "yesterday"

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Invalid time"):
            parse_time_spec("abc")

    def test_whitespace_stripped(self):
        result = parse_time_spec("  1h  ")
        assert result
