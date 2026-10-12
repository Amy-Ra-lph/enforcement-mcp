"""Fuzz tests for parsers using Hypothesis.

Goal: no parser crashes on arbitrary input. Every parser must either return
a valid result or raise InputTooLargeError — never an unhandled exception.
"""

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from enforcement_mcp.parsers._hardening import InputTooLargeError
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

FUZZ_SETTINGS = settings(
    max_examples=200,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=5000,
)

# Strategy: realistic-ish CLI output lines mixed with garbage
cli_output = st.text(
    alphabet=st.characters(codec="utf-8", categories=("L", "N", "P", "S", "Z")),
    min_size=0,
    max_size=50000,
)

# Strategy: lines that look like file paths
path_lines = st.from_regex(r"/[a-zA-Z0-9_./-]{0,200}", fullmatch=True)

# Strategy: lines that look like AVC denials
avc_line = st.builds(
    lambda perm, comm, path, stype, ttype: (
        f'type=AVC msg=audit(1): avc:  denied  {{ {perm} }} for pid=1234 '
        f'comm="{comm}" path="{path}" '
        f'scontext=system_u:system_r:{stype}:s0 '
        f'tcontext=system_u:object_r:{ttype}:s0 tclass=file permissive=0'
    ),
    perm=st.sampled_from(["read", "write", "execute", "open", "getattr"]),
    comm=st.from_regex(r"[a-z]{1,15}", fullmatch=True),
    path=st.from_regex(r"/[a-z0-9/_.]{1,50}", fullmatch=True),
    stype=st.from_regex(r"[a-z_]{3,20}_t", fullmatch=True),
    ttype=st.from_regex(r"[a-z_]{3,20}_t", fullmatch=True),
)


class TestAusearchFuzz:
    @given(cli_output)
    @FUZZ_SETTINGS
    def test_parse_avc_denials_no_crash(self, data):
        try:
            result = parse_avc_denials(data)
            assert isinstance(result, list)
        except InputTooLargeError:
            pass

    @given(cli_output)
    @FUZZ_SETTINGS
    def test_parse_fanotify_denials_no_crash(self, data):
        try:
            result = parse_fanotify_denials(data)
            assert isinstance(result, list)
        except InputTooLargeError:
            pass

    @given(st.lists(avc_line, min_size=0, max_size=20).map("\n".join))
    @FUZZ_SETTINGS
    def test_parse_avc_structured_fuzz(self, data):
        result = parse_avc_denials(data)
        assert isinstance(result, list)
        for denial in result:
            if "path" in denial:
                assert "\x00" not in denial["path"]


class TestFapolicydFuzz:
    @given(cli_output)
    @FUZZ_SETTINGS
    def test_parse_fapolicyd_list_no_crash(self, data):
        try:
            result = parse_fapolicyd_list(data)
            assert isinstance(result, list)
        except InputTooLargeError:
            pass

    @given(cli_output)
    @FUZZ_SETTINGS
    def test_parse_fapolicyd_dumpdb_no_crash(self, data):
        try:
            result = parse_fapolicyd_dumpdb(data)
            assert isinstance(result, list)
        except InputTooLargeError:
            pass

    @given(cli_output)
    @FUZZ_SETTINGS
    def test_parse_fapolicyd_rules_no_crash(self, data):
        try:
            result = parse_fapolicyd_rules(data)
            assert isinstance(result, list)
        except InputTooLargeError:
            pass


class TestSelinuxFuzz:
    @given(cli_output)
    @FUZZ_SETTINGS
    def test_parse_getenforce_no_crash(self, data):
        try:
            result = parse_getenforce(data)
            assert isinstance(result, str)
        except InputTooLargeError:
            pass

    @given(cli_output)
    @FUZZ_SETTINGS
    def test_parse_getsebool_no_crash(self, data):
        try:
            result = parse_getsebool(data)
            assert isinstance(result, list)
        except InputTooLargeError:
            pass

    @given(cli_output)
    @FUZZ_SETTINGS
    def test_parse_sesearch_allow_no_crash(self, data):
        try:
            result = parse_sesearch_allow(data)
            assert isinstance(result, list)
        except InputTooLargeError:
            pass

    @given(cli_output)
    @FUZZ_SETTINGS
    def test_parse_matchpathcon_no_crash(self, data):
        try:
            result = parse_matchpathcon(data)
            assert isinstance(result, dict)
        except InputTooLargeError:
            pass

    @given(cli_output)
    @FUZZ_SETTINGS
    def test_parse_semanage_login_no_crash(self, data):
        try:
            result = parse_semanage_login(data)
            assert isinstance(result, list)
        except InputTooLargeError:
            pass


class TestAideFuzz:
    @given(cli_output)
    @FUZZ_SETTINGS
    def test_parse_aide_check_no_crash(self, data):
        try:
            result = parse_aide_check(data)
            assert result.added >= 0
            assert result.removed >= 0
            assert result.changed >= 0
            for change in result.changes:
                assert "\x00" not in change.path
                assert change.path.startswith("/")
        except InputTooLargeError:
            pass

    @given(cli_output)
    @FUZZ_SETTINGS
    def test_parse_aide_config_no_crash(self, data):
        try:
            result = parse_aide_config(data)
            assert isinstance(result.rules, list)
            assert isinstance(result.custom_rules, list)
        except InputTooLargeError:
            pass


class TestTimeUtilsFuzz:
    @given(st.text(min_size=0, max_size=100))
    @FUZZ_SETTINGS
    def test_parse_time_spec_no_crash(self, data):
        try:
            result = parse_time_spec(data)
            assert isinstance(result, str)
        except (ValueError, InputTooLargeError):
            pass


class TestNullByteInjection:
    """Targeted: ensure no parser ever returns a path containing null bytes."""

    PAYLOADS = [
        "/etc/passwd\x00",
        "/etc/shadow\x00.txt",
        "\x00/root/.ssh/id_rsa",
        "/tmp/\x00../../etc/shadow",
    ]

    def test_avc_null_paths(self):
        for payload in self.PAYLOADS:
            raw = (
                f'type=AVC msg=audit(1): avc:  denied  {{ read }} for pid=1 '
                f'comm="test" path="{payload}" '
                f'scontext=u:r:t:s0 tcontext=u:r:t:s0 tclass=file permissive=0'
            )
            for d in parse_avc_denials(raw):
                assert "path" not in d or "\x00" not in d["path"]

    def test_fapolicyd_null_paths(self):
        for payload in self.PAYLOADS:
            raw = f"{payload} 12345 abc123\n"
            for e in parse_fapolicyd_list(raw):
                assert "\x00" not in e["path"]

    def test_aide_null_paths(self):
        for payload in self.PAYLOADS:
            raw = (
                "Changed entries:\n"
                "---------------------------------------------------\n"
                f"f > ...   ..H.... : {payload}\n"
            )
            for c in parse_aide_check(raw).changes:
                assert "\x00" not in c.path
