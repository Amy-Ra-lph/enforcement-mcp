"""Tests for ausearch parser."""

from pathlib import Path

from enforcement_mcp.parsers.ausearch import parse_avc_denials, parse_fanotify_denials

FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestParseAvcDenials:
    def test_parses_real_rhel9_output(self):
        raw = (FIXTURES / "ausearch_avc_rhel9.txt").read_text()
        result = parse_avc_denials(raw)
        assert isinstance(result, list)
        assert len(result) == 3
        for denial in result:
            assert "source_type" in denial
            assert "target_type" in denial
            assert "tclass" in denial
            assert "permission" in denial or "permissions" in denial
            assert "timestamp" in denial

    def test_first_denial_fields(self):
        raw = (FIXTURES / "ausearch_avc_rhel9.txt").read_text()
        result = parse_avc_denials(raw)
        d = result[0]
        assert d["source_type"] == "httpd_t"
        assert d["target_type"] == "user_home_t"
        assert d["tclass"] == "file"
        assert d["permission"] == "read"
        assert d["pid"] == 4821
        assert d["comm"] == "httpd"
        assert d["permissive"] is False

    def test_multi_permission_denial(self):
        raw = (FIXTURES / "ausearch_avc_rhel9.txt").read_text()
        result = parse_avc_denials(raw)
        d = result[2]
        assert d["permissions"] == ["getattr", "write"]
        assert d["permission"] == ["getattr", "write"]

    def test_empty_output(self):
        assert parse_avc_denials("<no matches>\n") == []

    def test_no_matches_text(self):
        assert parse_avc_denials("no matches\n") == []

    def test_blank(self):
        assert parse_avc_denials("") == []


class TestParseFanotifyDenials:
    def test_no_matches(self):
        raw = (FIXTURES / "ausearch_fanotify_rhel9.txt").read_text()
        result = parse_fanotify_denials(raw)
        assert result == []

    def test_empty_output(self):
        assert parse_fanotify_denials("<no matches>\n") == []

    def test_synthetic_fanotify(self):
        raw = (
            "----\n"
            "time->Wed Oct  8 14:40:00 2026\n"
            'type=FANOTIFY msg=audit(1760013600.123:100): resp=2 '
            'pid=5678 uid=1000 exe="/tmp/payload" '
            'subj=unconfined_u:unconfined_r:unconfined_t:s0 obj_trust=0\n'
        )
        result = parse_fanotify_denials(raw)
        assert len(result) == 1
        assert result[0]["decision"] == "deny"
        assert result[0]["pid"] == 5678
        assert result[0]["obj_trust"] == 0
