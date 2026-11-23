"""Configurable posture scoring profiles mapped to industry standards."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScoringProfile:
    """Penalty weights for posture score calculation.

    Each weight maps to a specific control ID in the profile's framework.
    Score starts at 100 and deducts penalties. Floor is 0.
    Critical rules trigger immediate FAIL regardless of score.
    """

    name: str
    framework: str
    selinux_not_enforcing: int
    avc_per_denial: int
    avc_cap: int
    fapolicyd_not_installed: int
    fapolicyd_inactive: int
    aide_not_configured: int
    aide_per_change: int
    aide_change_cap: int
    bool_threshold: int
    bool_penalty: int
    control_ids: dict[str, str] = field(default_factory=dict)
    critical_rules: dict[str, bool] = field(default_factory=dict)


NIST = ScoringProfile(
    name="nist",
    framework="NIST SP 800-53 Rev 5 / 800-53B",
    selinux_not_enforcing=30,
    avc_per_denial=2,
    avc_cap=20,
    fapolicyd_not_installed=20,
    fapolicyd_inactive=15,
    aide_not_configured=15,
    aide_per_change=3,
    aide_change_cap=15,
    bool_threshold=5,
    bool_penalty=5,
    control_ids={
        "selinux_mode": "AC-3 (Access Enforcement) — Low baseline",
        "avc_denials": "AU-2 (Event Logging) — Low baseline",
        "fapolicyd": "CM-14 (Signed Components) + CM-6 (Config Settings) — Moderate baseline",
        "aide": "SI-7 (Software, Firmware, and Information Integrity) — Moderate baseline",
        "booleans": "CM-6 (Configuration Settings) — Low baseline",
    },
    critical_rules={
        "selinux_not_enforcing": True,
        "aide_not_configured": True,
        "fapolicyd_not_installed": False,
    },
)

CIS = ScoringProfile(
    name="cis",
    framework="CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0",
    selinux_not_enforcing=25,
    avc_per_denial=1,
    avc_cap=15,
    fapolicyd_not_installed=15,
    fapolicyd_inactive=10,
    aide_not_configured=20,
    aide_per_change=2,
    aide_change_cap=10,
    bool_threshold=5,
    bool_penalty=5,
    control_ids={
        "selinux_mode": "1.5.1.3 Ensure SELinux mode is enforcing (L1, Scored)",
        "avc_denials": "Runtime finding (not scored by CIS)",
        "fapolicyd": "1.4.x Application whitelisting (L2, Scored)",
        "aide": "1.3.1 Ensure AIDE is installed (L1, Scored)",
        "booleans": "1.5.1.4+ SELinux booleans (L2, Not Scored)",
    },
    critical_rules={
        "selinux_not_enforcing": True,
        "aide_not_configured": True,
        "fapolicyd_not_installed": False,
    },
)

STIG = ScoringProfile(
    name="stig",
    framework="DISA RHEL 9 STIG V2R9",
    selinux_not_enforcing=20,
    avc_per_denial=1,
    avc_cap=10,
    fapolicyd_not_installed=20,
    fapolicyd_inactive=15,
    aide_not_configured=20,
    aide_per_change=2,
    aide_change_cap=10,
    bool_threshold=5,
    bool_penalty=5,
    control_ids={
        "selinux_mode": "RHEL-09-431010 / V-258078 (CAT I)",
        "avc_denials": "Runtime finding (no STIG rule)",
        "fapolicyd": "RHEL-09-653010 / V-258089 (CAT II)",
        "aide": "RHEL-09-651010 / V-258134 (CAT I)",
        "booleans": "RHEL-09-431025 (CAT II)",
    },
    critical_rules={
        "selinux_not_enforcing": True,
        "aide_not_configured": True,
        "fapolicyd_not_installed": True,
    },
)

CCSS = ScoringProfile(
    name="ccss",
    framework="NISTIR 7502 — Common Configuration Scoring System",
    selinux_not_enforcing=28,
    avc_per_denial=2,
    avc_cap=20,
    fapolicyd_not_installed=18,
    fapolicyd_inactive=14,
    aide_not_configured=16,
    aide_per_change=2,
    aide_change_cap=12,
    bool_threshold=5,
    bool_penalty=3,
    control_ids={
        "selinux_mode": "CCSS Base ~7.0 (AV:L/AC:L/Au:N/C:C/I:C/A:N)",
        "avc_denials": "CCSS per-denial dynamic scoring",
        "fapolicyd": "CCSS Base ~4.5 (AV:L/AC:L/Au:N/C:N/I:P/A:N)",
        "aide": "CCSS Base ~4.0 (AV:L/AC:L/Au:N/C:N/I:P/A:N)",
        "booleans": "CCSS Base ~1.0",
    },
    critical_rules={
        "selinux_not_enforcing": True,
        "aide_not_configured": False,
        "fapolicyd_not_installed": False,
    },
)

PROFILES: dict[str, ScoringProfile] = {
    "nist": NIST,
    "cis": CIS,
    "stig": STIG,
    "ccss": CCSS,
}

DEFAULT_PROFILE = NIST


def get_profile(name: str | None = None) -> ScoringProfile:
    if name is None:
        return DEFAULT_PROFILE
    profile = PROFILES.get(name.lower())
    if profile is None:
        valid = ", ".join(sorted(PROFILES))
        raise ValueError(f"Unknown scoring profile {name!r}. Valid: {valid}")
    return profile


def compute_score(
    profile: ScoringProfile,
    *,
    mode: str,
    denial_count: int,
    fap_installed: bool,
    fap_active: bool,
    aide_configured: bool,
    aide_changes: int,
    non_default_bools: int,
) -> tuple[int, list[dict], str]:
    """Compute posture score, findings, and pass/fail verdict.

    Returns (score, findings, verdict) where verdict is "PASS" or "FAIL".
    Critical findings set verdict to FAIL regardless of score.
    Each finding has penalty, description, control_id, and severity fields.
    """
    score = 100
    findings: list[dict] = []
    has_critical = False

    def _is_critical(rule_key: str) -> bool:
        return profile.critical_rules.get(rule_key, False)

    if mode != "enforcing":
        p = profile.selinux_not_enforcing
        crit = _is_critical("selinux_not_enforcing")
        score -= p
        if crit:
            has_critical = True
        findings.append({
            "penalty": p,
            "description": f"SELinux mode is {mode}, not enforcing",
            "control_id": profile.control_ids.get("selinux_mode", ""),
            "severity": "CRITICAL" if crit else "HIGH",
        })

    if denial_count > 0:
        p = min(denial_count * profile.avc_per_denial, profile.avc_cap)
        score -= p
        findings.append({
            "penalty": p,
            "description": f"{denial_count} AVC denials in last 24h",
            "control_id": profile.control_ids.get("avc_denials", ""),
            "severity": "MEDIUM",
        })

    if not fap_installed:
        p = profile.fapolicyd_not_installed
        crit = _is_critical("fapolicyd_not_installed")
        score -= p
        if crit:
            has_critical = True
        findings.append({
            "penalty": p,
            "description": "fapolicyd not installed",
            "control_id": profile.control_ids.get("fapolicyd", ""),
            "severity": "CRITICAL" if crit else "HIGH",
        })
    elif not fap_active:
        p = profile.fapolicyd_inactive
        score -= p
        findings.append({
            "penalty": p,
            "description": "fapolicyd installed but not active",
            "control_id": profile.control_ids.get("fapolicyd", ""),
            "severity": "HIGH",
        })

    if not aide_configured:
        p = profile.aide_not_configured
        crit = _is_critical("aide_not_configured")
        score -= p
        if crit:
            has_critical = True
        findings.append({
            "penalty": p,
            "description": "AIDE not configured or database missing",
            "control_id": profile.control_ids.get("aide", ""),
            "severity": "CRITICAL" if crit else "HIGH",
        })
    elif aide_changes > 0:
        p = min(aide_changes * profile.aide_per_change, profile.aide_change_cap)
        score -= p
        findings.append({
            "penalty": p,
            "description": f"AIDE detected {aide_changes} changes since baseline",
            "control_id": profile.control_ids.get("aide", ""),
            "severity": "MEDIUM",
        })

    if non_default_bools > profile.bool_threshold:
        p = profile.bool_penalty
        score -= p
        findings.append({
            "penalty": p,
            "description": f"{non_default_bools} non-default SELinux booleans enabled",
            "control_id": profile.control_ids.get("booleans", ""),
            "severity": "LOW",
        })

    verdict = "FAIL" if has_critical else "PASS"
    return max(0, score), findings, verdict
