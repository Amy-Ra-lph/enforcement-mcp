"""Tests for risk scoring engine."""

from enforcement_mcp.risk import (
    score_boolean_change,
    score_fapolicyd_trust,
    score_module_change,
)


class TestScoreBooleanChange:
    def test_low_risk_boolean(self):
        result = score_boolean_change(
            name="httpd_enable_homedirs",
            new_value=True,
            rules_unlocked=[
                {"source": "httpd_t", "target": "user_home_t", "permissions": ["read"]},
            ],
            domains_affected=["httpd_t"],
        )
        assert result["risk_level"] == "low"
        assert result["risk_score"] <= 25
        assert result["recommendation"] == "proceed"

    def test_high_risk_boolean_sensitive_target(self):
        result = score_boolean_change(
            name="allow_shadow_access",
            new_value=True,
            rules_unlocked=[
                {"source": "httpd_t", "target": "shadow_t", "permissions": ["read"]},
                {"source": "httpd_t", "target": "passwd_t", "permissions": ["write"]},
                {"source": "httpd_t", "target": "etc_t", "permissions": ["write"]},
                {"source": "httpd_t", "target": "tmp_t", "permissions": ["execute"]},
                {"source": "httpd_t", "target": "bin_t", "permissions": ["execute"]},
                {"source": "httpd_t", "target": "lib_t", "permissions": ["read"]},
            ],
            domains_affected=["httpd_t"],
        )
        assert result["risk_score"] > 25
        assert result["risk_level"] in ("medium", "high", "critical")

    def test_reversibility_info(self):
        result = score_boolean_change(
            name="httpd_enable_homedirs",
            new_value=True,
            rules_unlocked=[],
            domains_affected=[],
        )
        assert result["reversibility"]["difficulty"] == "easy"
        assert "setsebool" in result["reversibility"]["method"]

    def test_many_rules_high_blast_radius(self):
        rules = [
            {"source": "httpd_t", "target": f"type_{i}_t", "permissions": ["read"]}
            for i in range(25)
        ]
        result = score_boolean_change(
            name="big_boolean",
            new_value=True,
            rules_unlocked=rules,
            domains_affected=["httpd_t"],
        )
        assert result["risk_score"] >= 25


class TestScoreModuleChange:
    def test_small_containment_module(self):
        result = score_module_change(
            name="emcp_cve_2024_6387_minimal",
            cil_rules=[
                {"source": "sshd_t", "target": "tmp_t", "permissions": ["write"]},
            ],
            is_containment=True,
        )
        assert result["risk_score"] < 50
        assert "semodule -r" in result["reversibility"]["method"]

    def test_large_non_containment_module(self):
        rules = [
            {"source": "httpd_t", "target": "shadow_t", "permissions": ["read", "write"]},
            {"source": "httpd_t", "target": "kernel_t", "permissions": ["execmem"]},
        ] * 6
        result = score_module_change(
            name="dangerous_module",
            cil_rules=rules,
            is_containment=False,
        )
        assert result["risk_score"] > 25

    def test_containment_discount(self):
        rules = [{"source": "httpd_t", "target": "tmp_t", "permissions": ["read"]}]
        normal = score_module_change("mod1", rules, is_containment=False)
        contained = score_module_change("mod2", rules, is_containment=True)
        assert contained["risk_score"] <= normal["risk_score"]


class TestScoreFapolicydTrust:
    def test_safe_path(self):
        result = score_fapolicyd_trust(path="/usr/bin/myapp")
        assert result["risk_level"] == "low"

    def test_tmp_path_high_risk(self):
        result = score_fapolicyd_trust(path="/tmp/suspicious")
        assert result["risk_score"] >= 25

    def test_setuid_adds_risk(self):
        normal = score_fapolicyd_trust(path="/opt/app/bin", is_setuid=False)
        setuid = score_fapolicyd_trust(path="/opt/app/bin", is_setuid=True)
        assert setuid["risk_score"] > normal["risk_score"]
