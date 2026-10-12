"""Generate remediation playbooks using linux-system-roles.

Read-only: produces YAML text, never executes. Each playbook includes
a risk assessment so the reviewer knows what they're approving.
"""

from __future__ import annotations

import yaml

from enforcement_mcp.parsers import parse_sesearch_allow
from enforcement_mcp.risk import (
    score_boolean_change,
    score_fapolicyd_trust,
    score_module_change,
)
from enforcement_mcp.ssh import SSHBackend

SYSTEM_ROLES_COLLECTION = "fedora.linux_system_roles"


def _playbook_header(description: str, target: str = "{{ target_hosts }}") -> dict:
    return {
        "name": description,
        "hosts": target,
        "become": True,
    }


def _risk_comment(risk: dict) -> str:
    level = risk.get("risk_level", "unknown")
    score = risk.get("risk_score", -1)
    rec = risk.get("recommendation", "unknown")
    lines = [
        f"Risk: {level} ({score}/100) — {rec}",
    ]
    blast = risk.get("blast_radius", {})
    if "rules_unlocked" in blast:
        lines.append(f"Blast radius: {blast['rules_unlocked']} rules unlocked")
    if "domains_affected" in blast:
        domains = blast["domains_affected"]
        if domains:
            lines.append(f"Domains affected: {', '.join(domains[:5])}")
    surface = risk.get("attack_surface_delta", {})
    perms = surface.get("permissions_granted", [])
    if perms:
        lines.append(f"Permissions granted: {', '.join(sorted(set(perms))[:10])}")
    rev = risk.get("reversibility", {})
    if rev.get("method"):
        lines.append(f"Rollback: {rev['method']}")
    return "\n# ".join(lines)


async def generate_playbook(
    ssh: SSHBackend | None,
    finding_type: str,
    **params,
) -> dict:
    """Generate a remediation playbook with risk assessment.

    finding_type: 'denial', 'file_context', 'fapolicyd_block', 'aide_change'
    Returns: {playbook: str, risk: dict, alternatives: list, finding_type: str}
    """
    match finding_type:
        case "denial":
            return await _remediate_denial(ssh, params)
        case "file_context":
            return _remediate_file_context(params)
        case "fapolicyd_block":
            return _remediate_fapolicyd(params)
        case "aide_change":
            return _remediate_aide(params)
        case _:
            return {
                "error": "unknown_finding_type",
                "finding_type": finding_type,
                "supported": [
                    "denial",
                    "file_context",
                    "fapolicyd_block",
                    "aide_change",
                ],
            }


async def _remediate_denial(ssh: SSHBackend | None, params: dict) -> dict:
    source = str(params.get("source_type", ""))
    target = str(params.get("target_type", ""))
    tclass = str(params.get("tclass", ""))
    permission = str(params.get("permission", ""))
    path = params.get("path")

    if not all([source, target, tclass, permission]):
        return {
            "error": "missing_params",
            "required": ["source_type", "target_type", "tclass", "permission"],
        }

    alternatives = []

    # Option 1 (narrowest): relabel the specific file
    if path:
        relabel_play = _playbook_header(
            f"Relabel {path} for {source} access"
        )
        relabel_play["roles"] = [{
            "role": f"{SYSTEM_ROLES_COLLECTION}.selinux",
            "vars": {
                "selinux_restore_dirs": [path],
            },
        }]
        relabel_risk = {
            "risk_score": 0, "risk_level": "low",
            "recommendation": "proceed",
            "reversibility": {
                "method": "restorecon is idempotent — no policy change",
                "difficulty": "trivial",
            },
        }
        alternatives.append({
            "strategy": "relabel",
            "scope": "narrowest — fixes one file, no policy change",
            "risk": relabel_risk,
            "playbook": _render_playbook(
                relabel_play,
                f"Relabel {path} to expected context",
                relabel_risk,
            ),
        })

    # Option 2: toggle a boolean (if one exists)
    if ssh:
        bool_candidates = await _find_boolean_for_denial(
            ssh, source, target, tclass, permission,
        )
        for bc in bool_candidates:
            risk = score_boolean_change(
                name=bc["name"],
                new_value=True,
                rules_unlocked=bc["rules_unlocked"],
                domains_affected=bc["domains_affected"],
            )
            play = _playbook_header(
                f"Enable {bc['name']} for {source} → {target}"
            )
            play["roles"] = [{
                "role": f"{SYSTEM_ROLES_COLLECTION}.selinux",
                "vars": {
                    "selinux_booleans": [{
                        "name": bc["name"],
                        "state": "on",
                        "persistent": True,
                    }],
                },
            }]
            alternatives.append({
                "strategy": "boolean",
                "scope": f"medium — enables {len(bc['rules_unlocked'])} rules",
                "boolean": bc["name"],
                "risk": risk,
                "playbook": _render_playbook(
                    play,
                    f"Enable boolean {bc['name']}",
                    risk,
                ),
            })

    # Option 3 (broadest): custom CIL module
    cil_content = (
        f"(allow {source} {target} ({tclass} ({permission})))"
    )
    cil_rules = [{
        "source": source, "target": target,
        "tclass": tclass, "permissions": [permission],
    }]
    module_risk = score_module_change(
        name=f"fix_{source}_{permission}",
        cil_rules=cil_rules,
    )
    module_play = _playbook_header(
        f"Load CIL module for {source} → {target}:{permission}"
    )
    module_play["roles"] = [{
        "role": f"{SYSTEM_ROLES_COLLECTION}.selinux",
        "vars": {
            "selinux_modules": [{
                "name": f"fix_{source}_{permission}",
                "state": "enabled",
                "content": cil_content,
                "priority": "400",
            }],
        },
    }]
    alternatives.append({
        "strategy": "custom_module",
        "scope": "narrow — single allow rule",
        "risk": module_risk,
        "playbook": _render_playbook(
            module_play,
            f"Custom CIL module: {source} → {target}:{permission}",
            module_risk,
        ),
    })

    # Sort by risk score ascending (safest first)
    alternatives.sort(key=lambda a: a["risk"].get("risk_score", 999))
    recommended = alternatives[0]

    return {
        "finding_type": "denial",
        "recommended": recommended,
        "alternatives": alternatives,
        "total_options": len(alternatives),
    }


def _remediate_file_context(params: dict) -> dict:
    path = str(params.get("path", ""))
    expected_type = params.get("expected_type")
    actual_type = params.get("actual_type")

    if not path:
        return {"error": "missing_params", "required": ["path"]}

    alternatives = []

    # Option 1: restorecon (relabel to expected)
    if expected_type and actual_type and expected_type != actual_type:
        play = _playbook_header(f"Restore context on {path}")
        play["roles"] = [{
            "role": f"{SYSTEM_ROLES_COLLECTION}.selinux",
            "vars": {
                "selinux_restore_dirs": [path],
            },
        }]
        risk = {"risk_score": 5, "risk_level": "low",
                "recommendation": "proceed",
                "reversibility": {"method": "restorecon is idempotent",
                                  "difficulty": "easy"}}
        alternatives.append({
            "strategy": "restorecon",
            "scope": "narrowest — relabels to expected context",
            "risk": risk,
            "playbook": _render_playbook(
                play, f"Restore {path} from {actual_type} to {expected_type}",
                risk,
            ),
        })

    # Option 2: set a permanent file context rule
    if expected_type:
        play = _playbook_header(
            f"Set file context {expected_type} on {path}"
        )
        play["roles"] = [{
            "role": f"{SYSTEM_ROLES_COLLECTION}.selinux",
            "vars": {
                "selinux_fcontexts": [{
                    "target": path,
                    "setype": expected_type,
                    "state": "present",
                }],
                "selinux_restore_dirs": [path],
            },
        }]
        risk = {"risk_score": 15, "risk_level": "low",
                "recommendation": "proceed",
                "reversibility": {
                    "method": f"semanage fcontext -d '{path}'",
                    "difficulty": "easy"}}
        alternatives.append({
            "strategy": "fcontext_rule",
            "scope": "permanent — survives relabel",
            "risk": risk,
            "playbook": _render_playbook(
                play, f"Permanent context rule for {path}", risk,
            ),
        })

    alternatives.sort(key=lambda a: a["risk"].get("risk_score", 999))
    recommended = alternatives[0] if alternatives else None

    return {
        "finding_type": "file_context",
        "recommended": recommended,
        "alternatives": alternatives,
        "total_options": len(alternatives),
    }


def _remediate_fapolicyd(params: dict) -> dict:
    path = str(params.get("path", ""))

    if not path:
        return {"error": "missing_params", "required": ["path"]}

    risk = score_fapolicyd_trust(path=path)

    play = _playbook_header(f"Trust {path} in fapolicyd")
    play["roles"] = [{
        "role": f"{SYSTEM_ROLES_COLLECTION}.fapolicyd",
        "vars": {
            "fapolicyd_add_trusted_paths": [path],
        },
    }]

    playbook_str = _render_playbook(
        play, f"Add {path} to fapolicyd trust", risk,
    )

    return {
        "finding_type": "fapolicyd_block",
        "recommended": {
            "strategy": "trust_path",
            "scope": "single binary",
            "risk": risk,
            "playbook": playbook_str,
        },
        "alternatives": [{
            "strategy": "trust_path",
            "scope": "single binary",
            "risk": risk,
            "playbook": playbook_str,
        }],
        "total_options": 1,
    }


def _remediate_aide(params: dict) -> dict:
    paths = params.get("changed_paths", [])
    action = str(params.get("action", "investigate"))

    if action == "accept":
        play = _playbook_header("Update AIDE baseline after verified changes")
        play["roles"] = [{
            "role": f"{SYSTEM_ROLES_COLLECTION}.aide",
            "vars": {
                "aide_update": True,
            },
        }]
        risk = {
            "risk_score": 35, "risk_level": "medium",
            "recommendation": "proceed_with_review",
            "blast_radius": {"files_accepted": len(paths)},
            "reversibility": {
                "method": "Restore previous aide.db.gz from backup",
                "difficulty": "medium",
            },
        }
        return {
            "finding_type": "aide_change",
            "recommended": {
                "strategy": "update_baseline",
                "scope": f"accept {len(paths)} changes into baseline",
                "risk": risk,
                "playbook": _render_playbook(
                    play, "Update AIDE baseline", risk,
                ),
            },
            "alternatives": [],
            "total_options": 1,
            "warning": (
                "Updating the baseline accepts ALL current changes. "
                "Verify every changed file is legitimate before running."
            ),
        }

    return {
        "finding_type": "aide_change",
        "action": "investigate",
        "changed_paths": paths,
        "message": (
            "AIDE detected changes. Investigate before accepting. "
            "Call with action='accept' after verification to generate "
            "the baseline update playbook."
        ),
        "total_options": 0,
    }


async def _find_boolean_for_denial(
    ssh: SSHBackend,
    source: str,
    target: str,
    tclass: str,
    permission: str,
) -> list[dict]:
    """Find booleans that would allow a denied operation."""
    cmd = (
        f"sesearch --allow -s {source} -t {target} "
        f"-c {tclass} -p {permission} -b 2>/dev/null"
    )
    result = await ssh.execute(cmd)
    if not result.success:
        return []

    rules = parse_sesearch_allow(result.stdout)
    bool_map: dict[str, dict] = {}
    for rule in rules:
        cond = rule.get("conditional")
        if not cond:
            continue
        if cond not in bool_map:
            bool_map[cond] = {
                "name": cond,
                "rules_unlocked": [],
                "domains_affected": set(),
            }
        bool_map[cond]["rules_unlocked"].append(rule)
        bool_map[cond]["domains_affected"].add(rule["source"])

    candidates = []
    for bc in bool_map.values():
        bc["domains_affected"] = list(bc["domains_affected"])
        candidates.append(bc)

    candidates.sort(key=lambda c: len(c["rules_unlocked"]))
    return candidates


def _render_playbook(play: dict, description: str, risk: dict) -> str:
    comment = _risk_comment(risk)
    playbook_yaml = yaml.dump(
        [play], default_flow_style=False, sort_keys=False,
    )
    return (
        f"# Remediation: {description}\n"
        f"# {comment}\n"
        f"# Generated by enforcement-mcp — review before applying\n"
        f"---\n{playbook_yaml}"
    )
