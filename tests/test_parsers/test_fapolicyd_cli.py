"""Tests for fapolicyd CLI parsers."""

from pathlib import Path

from enforcement_mcp.parsers.fapolicyd_cli import (
    parse_fapolicyd_dumpdb,
    parse_fapolicyd_list,
    parse_fapolicyd_rules,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestParseFapolicydList:
    def test_parses_real_rhel9_output(self):
        raw = (FIXTURES / "fapolicyd_list_rhel9.txt").read_text()
        result = parse_fapolicyd_list(raw)
        assert isinstance(result, list)

    def test_skips_language_header(self):
        raw = (FIXTURES / "fapolicyd_list_rhel9.txt").read_text()
        result = parse_fapolicyd_list(raw)
        for entry in result:
            assert not entry["path"].startswith("->")

    def test_empty(self):
        assert parse_fapolicyd_list("") == []


class TestParseFapolicydDumpdb:
    def test_parses_real_rhel9_output(self):
        raw = (FIXTURES / "fapolicyd_dumpdb_rhel9.txt").read_text()
        result = parse_fapolicyd_dumpdb(raw)
        assert isinstance(result, list)
        assert len(result) > 0
        for entry in result:
            assert "path" in entry
            assert "source" in entry

    def test_first_entry(self):
        raw = (FIXTURES / "fapolicyd_dumpdb_rhel9.txt").read_text()
        result = parse_fapolicyd_dumpdb(raw)
        assert result[0]["source"] == "rpmdb"
        assert "bash_completion" in result[0]["path"]

    def test_empty(self):
        assert parse_fapolicyd_dumpdb("") == []


class TestParseFapolicydRules:
    def test_parses_rule_lines(self):
        raw = "1. deny perm=execute all : all\n2. allow perm=any uid=0 : dir=/usr/\n"
        result = parse_fapolicyd_rules(raw)
        assert len(result) == 2
        assert result[0]["number"] == 1
        assert result[0]["decision"] == "deny"
        assert result[1]["number"] == 2
        assert result[1]["decision"] == "allow"

    def test_from_fixture(self):
        raw = (FIXTURES / "fapolicyd_list_rhel9.txt").read_text()
        result = parse_fapolicyd_rules(raw)
        assert isinstance(result, list)
        allows = [r for r in result if r.get("decision") == "allow"]
        assert len(allows) > 0

    def test_empty(self):
        assert parse_fapolicyd_rules("") == []
