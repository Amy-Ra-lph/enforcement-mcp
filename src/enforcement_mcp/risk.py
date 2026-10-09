"""Risk scoring engine for policy changes.

Scores 0-100 based on blast radius, permission severity, target sensitivity,
reversibility, least privilege gap, and lockout potential.
"""

SENSITIVE_TYPES = {
    "shadow_t": 30,
    "passwd_t": 25,
    "etc_t": 20,
    "sshd_key_t": 30,
    "admin_home_t": 20,
    "kernel_t": 30,
    "init_t": 25,
    "auditd_log_t": 25,
    "selinux_config_t": 30,
    "security_t": 30,
    "unlabeled_t": 15,
    "var_log_t": 15,
    "httpd_config_t": 10,
    "cert_t": 20,
}

HIGH_RISK_PERMISSIONS = {
    "execmem": 20,
    "execstack": 20,
    "execmod": 20,
    "admin": 25,
    "relabelto": 25,
    "relabelfrom": 25,
    "transition": 15,
    "write": 10,
    "setattr": 10,
    "append": 5,
    "execute": 8,
    "execute_no_trans": 15,
    "create": 8,
    "unlink": 10,
    "mounton": 20,
    "quotaon": 15,
}

FAPOLICYD_PATH_RISK = {
    "/tmp": 30,
    "/var/tmp": 30,
    "/dev/shm": 30,
    "/home": 15,
    "/root": 25,
    "/opt": 5,
    "/usr/local": 5,
    "/usr/bin": 3,
    "/usr/sbin": 3,
    "/usr/lib": 3,
    "/usr/lib64": 3,
}


def score_boolean_change(
    name: str,
    new_value: bool,
    rules_unlocked: list[dict],
    domains_affected: list[str],
) -> dict:
    """Score risk of toggling an SELinux boolean."""
    factors = []
    score = 0

    blast = len(rules_unlocked)
    if blast > 20:
        score += 25
        factors.append({"factor": "blast_radius", "value": blast, "penalty": 25})
    elif blast > 5:
        score += 15
        factors.append({"factor": "blast_radius", "value": blast, "penalty": 15})
    elif blast > 0:
        score += 5
        factors.append({"factor": "blast_radius", "value": blast, "penalty": 5})

    perm_penalty = 0
    for rule in rules_unlocked:
        for perm in rule.get("permissions", []):
            perm_penalty = max(perm_penalty, HIGH_RISK_PERMISSIONS.get(perm, 0))
    if perm_penalty:
        score += perm_penalty
        factors.append({"factor": "permission_severity", "penalty": perm_penalty})

    target_penalty = 0
    for rule in rules_unlocked:
        target = rule.get("target", "")
        target_penalty = max(target_penalty, SENSITIVE_TYPES.get(target, 0))
    if target_penalty:
        score += target_penalty
        factors.append({"factor": "target_sensitivity", "penalty": target_penalty})

    factors.append({
        "factor": "reversibility",
        "value": "easy",
        "penalty": 0,
        "note": f"setsebool -P {name} {'off' if new_value else 'on'}",
    })

    score = min(100, score)
    level = _score_to_level(score)

    return {
        "risk_score": score,
        "risk_level": level,
        "blast_radius": {
            "rules_unlocked": len(rules_unlocked),
            "domains_affected": domains_affected,
        },
        "attack_surface_delta": {
            "permissions_granted": [
                p for r in rules_unlocked for p in r.get("permissions", [])
            ],
        },
        "reversibility": {
            "method": f"setsebool -P {name} {'off' if new_value else 'on'}",
            "difficulty": "easy",
        },
        "recommendation": _recommendation(level),
        "factors": factors,
    }


def score_module_change(
    name: str,
    cil_rules: list[dict],
    is_containment: bool = False,
) -> dict:
    """Score risk of loading a CIL policy module."""
    factors = []
    score = 0

    blast = len(cil_rules)
    if blast > 10:
        score += 20
        factors.append({"factor": "blast_radius", "value": blast, "penalty": 20})
    elif blast > 3:
        score += 10
        factors.append({"factor": "blast_radius", "value": blast, "penalty": 10})
    else:
        score += 3
        factors.append({"factor": "blast_radius", "value": blast, "penalty": 3})

    perm_penalty = 0
    for rule in cil_rules:
        for perm in rule.get("permissions", []):
            perm_penalty = max(perm_penalty, HIGH_RISK_PERMISSIONS.get(perm, 0))
    if perm_penalty:
        score += perm_penalty
        factors.append({"factor": "permission_severity", "penalty": perm_penalty})

    target_penalty = 0
    for rule in cil_rules:
        target = rule.get("target", "")
        target_penalty = max(target_penalty, SENSITIVE_TYPES.get(target, 0))
    if target_penalty:
        score += target_penalty
        factors.append({"factor": "target_sensitivity", "penalty": target_penalty})

    factors.append({
        "factor": "reversibility",
        "value": "easy",
        "penalty": 0,
        "note": f"semodule -r {name}",
    })

    if is_containment:
        score = max(0, score - 10)
        factors.append({
            "factor": "containment_discount",
            "penalty": -10,
            "note": "Containment modules reduce attack surface",
        })

    score = min(100, score)
    level = _score_to_level(score)

    return {
        "risk_score": score,
        "risk_level": level,
        "blast_radius": {"rules_in_module": blast},
        "attack_surface_delta": {
            "permissions_granted": [
                p for r in cil_rules for p in r.get("permissions", [])
            ],
        },
        "reversibility": {
            "method": f"semodule -r {name}",
            "difficulty": "easy",
        },
        "recommendation": _recommendation(level),
        "factors": factors,
    }


def score_fapolicyd_trust(path: str, is_setuid: bool = False) -> dict:
    """Score risk of adding a binary to fapolicyd trust."""
    factors = []
    score = 0

    path_risk = 0
    for prefix, risk in FAPOLICYD_PATH_RISK.items():
        if path.startswith(prefix):
            path_risk = max(path_risk, risk)
    if path_risk:
        score += path_risk
        factors.append({"factor": "location_risk", "value": path, "penalty": path_risk})

    if is_setuid:
        score += 20
        factors.append({"factor": "setuid", "penalty": 20})

    factors.append({
        "factor": "reversibility",
        "value": "easy",
        "penalty": 0,
        "note": f"fapolicyd-cli --file delete {path} && fapolicyd-cli --update",
    })

    score = min(100, score)
    level = _score_to_level(score)

    return {
        "risk_score": score,
        "risk_level": level,
        "blast_radius": {"path": path},
        "attack_surface_delta": {"binary_trusted": path},
        "reversibility": {
            "method": f"fapolicyd-cli --file delete {path} && fapolicyd-cli --update",
            "difficulty": "easy",
        },
        "recommendation": _recommendation(level),
        "factors": factors,
    }


def _score_to_level(score: int) -> str:
    if score <= 25:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 75:
        return "high"
    return "critical"


def _recommendation(level: str) -> str:
    match level:
        case "low":
            return "proceed"
        case "medium":
            return "proceed_with_review"
        case "high":
            return "recommend_alternative"
        case "critical":
            return "refuse"
        case _:
            return "proceed"
