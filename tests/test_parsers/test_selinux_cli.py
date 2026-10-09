"""Tests for SELinux CLI parsers."""

from pathlib import Path

from enforcement_mcp.parsers.selinux_cli import (
    parse_getenforce,
    parse_getsebool,
    parse_matchpathcon,
    parse_semanage_login,
    parse_sesearch_allow,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestParseGetenforce:
    def test_enforcing(self):
        assert parse_getenforce("Enforcing\n") == "enforcing"

    def test_permissive(self):
        assert parse_getenforce("Permissive\n") == "permissive"

    def test_disabled(self):
        raw = (FIXTURES / "getenforce_disabled.txt").read_text()
        assert parse_getenforce(raw) == "disabled"


class TestParseGetsebool:
    def test_parses_real_rhel9_output(self):
        raw = (FIXTURES / "getsebool_rhel9.txt").read_text()
        result = parse_getsebool(raw)
        assert isinstance(result, list)
        assert len(result) > 0
        for item in result:
            assert "name" in item
            assert "state" in item
            assert item["state"] in ("on", "off")

    def test_first_entry(self):
        raw = (FIXTURES / "getsebool_rhel9.txt").read_text()
        result = parse_getsebool(raw)
        assert result[0]["name"] == "abrt_anon_write"
        assert result[0]["state"] == "off"

    def test_single_line(self):
        result = parse_getsebool("httpd_enable_homedirs --> off\n")
        assert result == [{"name": "httpd_enable_homedirs", "state": "off"}]

    def test_empty(self):
        assert parse_getsebool("") == []


class TestParseSesearchAllow:
    def test_parses_real_rhel9_output(self):
        raw = (FIXTURES / "sesearch_allow_rhel9.txt").read_text()
        result = parse_sesearch_allow(raw)
        assert isinstance(result, list)
        assert len(result) > 0
        for rule in result:
            assert "source" in rule
            assert "target" in rule
            assert "tclass" in rule
            assert "permissions" in rule

    def test_conditional_rule(self):
        raw = (FIXTURES / "sesearch_allow_rhel9.txt").read_text()
        result = parse_sesearch_allow(raw)
        conditionals = [r for r in result if r.get("conditional")]
        assert len(conditionals) > 0
        for c in conditionals:
            assert isinstance(c["conditional_state"], bool)

    def test_multi_permission(self):
        raw = "allow httpd_t httpd_sys_content_t : file { read open getattr } ;\n"
        result = parse_sesearch_allow(raw)
        assert len(result) == 1
        assert set(result[0]["permissions"]) == {"read", "open", "getattr"}


class TestParseMatchpathcon:
    def test_real_output(self):
        raw = (FIXTURES / "matchpathcon_rhel9.txt").read_text()
        result = parse_matchpathcon(raw)
        assert result["path"] == "/var/www/html"
        assert result["type"] == "httpd_sys_content_t"
        assert result["context"] == "system_u:object_r:httpd_sys_content_t:s0"

    def test_no_match(self):
        raw = "/nonexistent\t<<none>>\n"
        result = parse_matchpathcon(raw)
        assert result["type"] is None


class TestParseSemanageLogin:
    def test_real_output(self):
        raw = (FIXTURES / "semanage_login_rhel9.txt").read_text()
        result = parse_semanage_login(raw)
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["login"] == "__default__"
        assert result[0]["selinux_user"] == "unconfined_u"
        assert result[0]["range"] == "s0-s0:c0.c1023"
