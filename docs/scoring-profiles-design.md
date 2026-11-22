# Posture Scoring Profiles — Design

## Problem

`host_posture()` in `tools/posture.py` uses hardcoded penalty weights with no documented rationale.
The weights are arbitrary round numbers: -30 for SELinux not enforcing, -15 for fapolicyd missing,
-5 for non-default booleans. No mapping to any industry standard, compliance framework, or risk
methodology. This makes the posture score indefensible to customers who need auditable scoring.

## Solution

Configurable scoring profiles mapped to industry standards. Ship four presets covering the major
customer segments. Each preset documents the control ID, framework reference, and rationale for
every penalty weight. Custom profiles supported via YAML config.

## Preset Profiles

### Penalty Comparison

All profiles start at 100 and subtract penalties. Floor is 0.

| Check | NIST 800-53 | CIS RHEL 9 | DISA STIG | CCSS |
|-------|-------------|------------|-----------|------|
| SELinux not enforcing | -30 | -25 | -20 | -28 |
| AVC denials (per denial) | -2, cap -20 | -1, cap -15 | -1, cap -10 | dynamic |
| fapolicyd not installed | -20 | -15 | -20 | -18 |
| fapolicyd installed, inactive | -15 | -10 | -15 | -14 |
| AIDE not configured | -15 | -20 | -20 | -16 |
| AIDE changes (per change) | -3, cap -15 | -2, cap -10 | -2, cap -10 | dynamic |
| >5 non-default booleans | -5 | -5 | -5 | -3 |

### NIST 800-53 Baseline (default)

**Standard:** NIST SP 800-53 Rev 5 + SP 800-53B control baselines
**Audience:** Federal agencies, FedRAMP, any org following the NIST RMF

Weights derived from which FIPS 199 baseline tier a control first appears in.
Controls present in the Low baseline are foundational (heaviest penalty).
Moderate-only controls are defense-in-depth (mid-weight).

| Check | Control | Baseline | Penalty | Rationale |
|-------|---------|----------|---------|-----------|
| SELinux mode | AC-3 (Access Enforcement) | Low | -30 | Foundational MAC — in all three baselines |
| AVC denials | AU-2 (Event Logging) | Low | -2/ea, -20 cap | Symptoms of enforcement working; scored lower than config |
| fapolicyd installed | CM-14 (Signed Components) + CM-6 | Moderate | -20 | Application whitelisting, defense-in-depth |
| fapolicyd inactive | CM-14 + CM-6 | Moderate | -15 | Installed but not protecting |
| AIDE configured | SI-7 (Integrity) | Moderate | -15 | File integrity verification |
| AIDE changes | SI-7 enhancements | Moderate | -3/ea, -15 cap | Integrity deviations from baseline |
| Non-default booleans | CM-6 (Config Settings) | Low | -5 | Config drift indicator |

### CIS RHEL 9 Benchmark

**Standard:** CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0
**Audience:** Commercial enterprises, PCI DSS environments, compliance auditors

Weights derived from CIS level and scored/not-scored designation.
L1 Scored = highest weight (expected on every system).
L2 Scored = mid-weight (defense-in-depth, may reduce functionality).
Not Scored = advisory, minimal penalty.

| Check | CIS Section | Level | Scored | Penalty |
|-------|-------------|-------|--------|---------|
| SELinux mode | 1.5.1.3 | L1 | Yes | -25 |
| AVC denials | — | — | No | -1/ea, -15 cap |
| fapolicyd installed | 1.4.x | L2 | Yes | -15 |
| fapolicyd inactive | 1.4.x | L2 | Yes | -10 |
| AIDE configured | 1.3.1 | L1 | Yes | -20 |
| AIDE changes | — | — | No | -2/ea, -10 cap |
| Non-default booleans | 1.5.1.4+ | L2 | No | -5 |

### DISA STIG

**Standard:** DISA RHEL 9 STIG V2R9
**Audience:** DoD, defense contractors, systems requiring ATO

Weights derived from CAT severity: CAT I = -30, CAT II = -20, CAT III = -5.
All enforcement-mcp checks map to CAT II. STIGs assess configuration state only,
not runtime findings (denials).

| Check | Rule ID | Vuln ID | CAT | Penalty |
|-------|---------|---------|-----|---------|
| SELinux mode | RHEL-09-431010 | V-258078 | II | -20 |
| AVC denials | — | — | — | -1/ea, -10 cap |
| fapolicyd installed | RHEL-09-653010 | V-258089 | II | -20 |
| fapolicyd inactive | RHEL-09-653010 | V-258089 | II | -15 |
| AIDE configured | RHEL-09-651010 | V-258134 | II | -20 |
| AIDE changes | RHEL-09-651015 | V-258135 | II | -2/ea, -10 cap |
| Non-default booleans | — | — | — | -5 |

### CCSS (Common Configuration Scoring System)

**Standard:** NISTIR 7502 — CVSS adapted for configuration issues (part of SCAP)
**Audience:** Security tool vendors, SCAP-compatible environments

Each check scored using CCSS base metrics (Access Vector, Complexity, Authentication, C/I/A Impact).
Penalty = `(ccss_score / 10) * max_budget`. AVC and AIDE change penalties are dynamic:
each denial/change gets its own CCSS vector based on the specific operation and target.

| Check | CCSS Base | Vector | Penalty |
|-------|-----------|--------|---------|
| SELinux mode | 7.0 | AV:L/AC:L/Au:N/C:C/I:C/A:N | -28 |
| fapolicyd installed | 4.5 | AV:L/AC:L/Au:N/C:N/I:P/A:N | -18 |
| fapolicyd inactive | 3.5 | AV:L/AC:L/Au:N/C:N/I:P/A:N | -14 |
| AIDE configured | 4.0 | AV:L/AC:L/Au:N/C:N/I:P/A:N | -16 |
| Non-default booleans | 1.0 | AV:L/AC:H/Au:N/C:N/I:P/A:N | -3 |
| AVC / AIDE changes | dynamic | Per-finding vector | 0.5-3.0 each |

## Output Format

The posture JSON includes the profile name and per-finding control references:

```json
{
  "posture_score": 65,
  "scoring_profile": "nist-800-53",
  "findings": [
    {
      "deduction": -10,
      "reason": "3 AVC denials in last 24h",
      "control": "AU-2",
      "framework": "NIST SP 800-53 Rev 5",
      "baseline": "Low"
    }
  ]
}
```

## Custom Profiles

Users provide a YAML file:

```yaml
name: acme-corp
description: Custom weights for ACME Corp risk posture
base_score: 100
penalties:
  selinux_not_enforcing: 35
  avc_denial_per: 3
  avc_denial_cap: 25
  fapolicyd_not_installed: 20
  fapolicyd_inactive: 15
  aide_not_configured: 20
  aide_change_per: 5
  aide_change_cap: 20
  non_default_booleans: 10
  non_default_booleans_threshold: 3
```

## Implementation

New module: `src/enforcement_mcp/scoring.py`

```python
@dataclass(frozen=True)
class ScoringProfile:
    name: str
    selinux_not_enforcing: int
    avc_per: int
    avc_cap: int
    fapolicyd_not_installed: int
    fapolicyd_inactive: int
    aide_not_configured: int
    aide_change_per: int
    aide_change_cap: int
    booleans_penalty: int
    booleans_threshold: int

PROFILES: dict[str, ScoringProfile] = {
    "nist-800-53": ScoringProfile("nist-800-53", 30, 2, 20, 20, 15, 15, 3, 15, 5, 5),
    "cis-rhel9":   ScoringProfile("cis-rhel9",   25, 1, 15, 15, 10, 20, 2, 10, 5, 5),
    "disa-stig":   ScoringProfile("disa-stig",    20, 1, 10, 20, 15, 20, 2, 10, 5, 5),
    "ccss":        ScoringProfile("ccss",         28, 2, 20, 18, 14, 16, 3, 15, 3, 5),
}

def load_custom_profile(path: str) -> ScoringProfile: ...
```

`host_posture()` signature change:

```python
async def host_posture(ssh: SSHBackend, profile: str = "nist-800-53") -> dict:
```

The profile is resolved from `PROFILES` dict or loaded from a YAML path. Scoring
logic replaces hardcoded constants with `profile.selinux_not_enforcing`, etc.
The profile name and per-finding control IDs are included in the returned dict.

## Migration

The current hardcoded weights roughly match NIST baseline-derived values.
Making `nist-800-53` the default preserves approximate backward compatibility.
No breaking change to the output schema — `scoring_profile` and `control`
fields are additive.
