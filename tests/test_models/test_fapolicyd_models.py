"""Tests for fapolicyd Pydantic models."""

from enforcement_mcp.models.fapolicyd import (
    FapolicydDenial,
    FapolicydRule,
    FapolicydStatus,
    TrustEntry,
)


class TestFapolicydDenial:
    def test_deny(self):
        d = FapolicydDenial(pid=1234, uid=1000, decision="deny", obj_trust=0)
        assert d.decision == "deny"


class TestFapolicydStatus:
    def test_active(self):
        s = FapolicydStatus(active=True, rules=15, trust_db_entries=48231)
        assert s.active is True


class TestTrustEntry:
    def test_untrusted(self):
        t = TrustEntry(path="/tmp/payload", trusted=False, reason="not in RPM database")
        assert t.trusted is False


class TestFapolicydRule:
    def test_deny_rule(self):
        r = FapolicydRule(number=1, decision="deny", raw="1. deny perm=execute all : all")
        assert r.decision == "deny"
