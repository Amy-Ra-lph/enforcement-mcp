"""Tests for parser input hardening — size limits and path sanitization."""

import pytest

from enforcement_mcp.parsers._hardening import (
    InputTooLargeError,
    MAX_INPUT_BYTES,
    sanitize_parsed_path,
    validate_input_size,
)
from enforcement_mcp.parsers.aide_cli import parse_aide_check, parse_aide_config
from enforcement_mcp.parsers.ausearch import parse_avc_denials, parse_fanotify_denials
from enforcement_mcp.parsers.fapolicyd_cli import (
    parse_fapolicyd_dumpdb,
    parse_fapolicyd_list,
    parse_fapolicyd_rules,
)
from enforcement_mcp.parsers.selinux_cli import (
    parse_getenforce,
    parse_getsebool,
    parse_matchpathcon,
    parse_semanage_login,
    parse_sesearch_allow,
)
from enforcement_mcp.parsers.time_utils import parse_time_spec


class TestInputSizeLimits:
    """Every parser rejects input over MAX_INPUT_BYTES."""

    def _oversized(self) -> str:
        return "x" * (MAX_INPUT_BYTES + 1)

    def test_parse_avc_denials_rejects_oversized(self):
        with pytest.raises(InputTooLargeError):
            parse_avc_denials(self._oversized())

    def test_parse_fanotify_denials_rejects_oversized(self):
        with pytest.raises(InputTooLargeError):
            parse_fanotify_denials(self._oversized())

    def test_parse_fapolicyd_list_rejects_oversized(self):
        with pytest.raises(InputTooLargeError):
            parse_fapolicyd_list(self._oversized())

    def test_parse_fapolicyd_dumpdb_rejects_oversized(self):
        with pytest.raises(InputTooLargeError):
            parse_fapolicyd_dumpdb(self._oversized())

    def test_parse_fapolicyd_rules_rejects_oversized(self):
        with pytest.raises(InputTooLargeError):
            parse_fapolicyd_rules(self._oversized())

    def test_parse_getenforce_rejects_oversized(self):
        with pytest.raises(InputTooLargeError):
            parse_getenforce(self._oversized())

    def test_parse_getsebool_rejects_oversized(self):
        with pytest.raises(InputTooLargeError):
            parse_getsebool(self._oversized())

    def test_parse_sesearch_allow_rejects_oversized(self):
        with pytest.raises(InputTooLargeError):
            parse_sesearch_allow(self._oversized())

    def test_parse_matchpathcon_rejects_oversized(self):
        with pytest.raises(InputTooLargeError):
            parse_matchpathcon(self._oversized())

    def test_parse_semanage_login_rejects_oversized(self):
        with pytest.raises(InputTooLargeError):
            parse_semanage_login(self._oversized())

    def test_parse_aide_check_rejects_oversized(self):
        with pytest.raises(InputTooLargeError):
            parse_aide_check(self._oversized())

    def test_parse_aide_config_rejects_oversized(self):
        with pytest.raises(InputTooLargeError):
            parse_aide_config(self._oversized())

    def test_parse_time_spec_rejects_oversized(self):
        with pytest.raises(InputTooLargeError):
            parse_time_spec(self._oversized())


class TestPathSanitization:
    """sanitize_parsed_path rejects malicious paths."""

    def test_null_byte_rejected(self):
        assert sanitize_parsed_path("/etc/passwd\x00.txt") is None

    def test_null_byte_at_start_rejected(self):
        assert sanitize_parsed_path("\x00/etc/passwd") is None

    def test_relative_path_rejected(self):
        assert sanitize_parsed_path("etc/passwd") is None

    def test_bare_filename_rejected(self):
        assert sanitize_parsed_path("passwd") is None

    def test_absolute_path_accepted(self):
        assert sanitize_parsed_path("/etc/passwd") == "/etc/passwd"

    def test_deep_path_accepted(self):
        assert sanitize_parsed_path("/var/lib/aide/aide.db.gz") == "/var/lib/aide/aide.db.gz"

    def test_exclusion_path_accepted(self):
        assert sanitize_parsed_path("!/etc/mtab") == "!/etc/mtab"

    def test_empty_string_rejected(self):
        assert sanitize_parsed_path("") is None

    def test_dot_rejected(self):
        assert sanitize_parsed_path(".") is None

    def test_dotdot_rejected(self):
        assert sanitize_parsed_path("..") is None


class TestPathSanitizationInParsers:
    """Parsers drop entries with null-byte paths."""

    def test_avc_denial_null_byte_path_dropped(self):
        raw = (
            "time->Mon Oct 12 10:00:00 2026\n"
            'type=AVC msg=audit(1): avc:  denied  { read } for pid=1234 '
            'comm="httpd" path="/etc/passwd\x00.evil" '
            "scontext=system_u:system_r:httpd_t:s0 "
            "tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0\n"
        )
        denials = parse_avc_denials(raw)
        assert len(denials) == 1
        assert "path" not in denials[0]

    def test_fapolicyd_list_null_byte_path_dropped(self):
        raw = "/usr/bin/ls 12345 abc123\n/usr/bin/cat\x00evil 12345 abc123\n"
        entries = parse_fapolicyd_list(raw)
        assert len(entries) == 1
        assert entries[0]["path"] == "/usr/bin/ls"

    def test_fapolicyd_dumpdb_null_byte_path_dropped(self):
        raw = "rpm /usr/bin/ls 12345 abc123\nrpm /usr/bin/cat\x00evil 12345 abc123\n"
        entries = parse_fapolicyd_dumpdb(raw)
        assert len(entries) == 1
        assert entries[0]["path"] == "/usr/bin/ls"

    def test_aide_check_null_byte_path_dropped(self):
        raw = (
            "AIDE found differences between database and filesystem!!\n"
            "Summary:\n"
            "  Total number of entries: 62150\n"
            "  Added entries: 0\n"
            "  Removed entries: 0\n"
            "  Changed entries: 2\n"
            "\n"
            "Changed entries:\n"
            "---------------------------------------------------\n"
            "f > ...   ..H.... : /etc/hosts\n"
            "f > ...   ..H.... : /etc/evil\x00path\n"
        )
        report = parse_aide_check(raw)
        assert len(report.changes) == 1
        assert report.changes[0].path == "/etc/hosts"
