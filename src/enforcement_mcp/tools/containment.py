"""CVE containment management tools."""

import json
import re

from enforcement_mcp.cve_api import fetch_cve, parse_cve_response
from enforcement_mcp.exploit_map import build_exploit_chain, map_cve_to_techniques
from enforcement_mcp.parsers import parse_getenforce, parse_sesearch_allow
from enforcement_mcp.risk import score_module_change
from enforcement_mcp.ssh import SSHBackend
from enforcement_mcp.tools.cve import CONTAINMENT_STATE_PATH, _infer_source_type


async def cve_contain(
    ssh: SSHBackend,
    cve_id: str,
    strategy: str = "minimal",
) -> dict:
    """Generate targeted containment policy for a CVE.

    Returns containment options with risk assessment. Does NOT auto-apply —
    the caller must explicitly confirm and call the apply step.
    """
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return {"error": "invalid_cve_id", "message": f"Invalid CVE ID format: {cve_id}"}

    mode = parse_getenforce((await ssh.execute("getenforce")).stdout)
    if mode == "disabled":
        return {
            "error": "selinux_disabled",
            "message": "SELinux is disabled — containment not possible",
        }

    raw = await fetch_cve(cve_id)
    if "error" in raw:
        return {"error": "cve_fetch_failed", "detail": raw}

    cve = parse_cve_response(raw)
    if not cve:
        return {"error": "cve_parse_failed", "cve_id": cve_id}

    source_type = _infer_source_type(cve.affected_packages)
    techniques = map_cve_to_techniques(cve.cwe, cve.affected_packages)
    chain = build_exploit_chain(source_type, techniques)

    gaps = []
    for step in chain:
        for perm in step["required_permissions"]:
            cmd = (
                f"sesearch --allow -s {perm['source']} -t {perm['target']} "
                f"-c {perm['class']} -p {perm['perm']} 2>/dev/null"
            )
            result = await ssh.execute(cmd)
            rules = parse_sesearch_allow(result.stdout)
            if rules:
                gaps.append({
                    "step": step["step"],
                    "technique": step["technique"],
                    "source": perm["source"],
                    "target": perm["target"],
                    "tclass": perm["class"],
                    "permission": perm["perm"],
                    "existing_rules": len(rules),
                })

    if not gaps:
        return {
            "cve": cve.model_dump(),
            "message": "Current policy already blocks all exploit steps — no containment needed",
            "containment_needed": False,
        }

    options = _generate_containment_options(cve_id, source_type, gaps, strategy)

    for opt in options:
        cil_rules = _cil_to_rule_dicts(opt["cil_content"])
        risk = score_module_change(
            name=opt["module_name"],
            cil_rules=cil_rules,
            is_containment=True,
        )
        opt["risk_assessment"] = risk

    options.sort(key=lambda o: (o.get("risk_assessment", {}).get("risk_score", 100)))

    return {
        "cve": cve.model_dump(),
        "source_type": source_type,
        "gaps_found": len(gaps),
        "gaps": gaps,
        "containment_needed": True,
        "options": options,
        "apply_instruction": (
            "To apply, use manage.load_module with the chosen option's "
            "module_name and cil_content, then track via manage.containment_expire."
        ),
    }


async def containment_expire(ssh: SSHBackend, cve_id: str) -> dict:
    """Remove a CVE containment module after patch is applied."""
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return {"error": "invalid_cve_id", "message": f"Invalid CVE ID format: {cve_id}"}

    state_result = await ssh.execute(f"cat {CONTAINMENT_STATE_PATH} 2>/dev/null")
    if not state_result.success or not state_result.stdout.strip():
        return {"error": "no_containments", "message": "No containment state file found"}

    try:
        containments = json.loads(state_result.stdout)
        if isinstance(containments, dict):
            containments = containments.get("containments", [])
    except json.JSONDecodeError:
        return {"error": "corrupt_state", "message": "Containment state file is corrupt"}

    target = None
    for c in containments:
        if c.get("cve_id") == cve_id:
            target = c
            break

    if not target:
        return {"error": "not_found", "message": f"No containment found for {cve_id}"}

    module_name = target.get("module_name", "")
    loaded = await ssh.execute(f"semodule -l 2>/dev/null | grep '^{module_name}'")
    if not loaded.stdout.strip():
        return {
            "cve_id": cve_id,
            "module_name": module_name,
            "status": "already_removed",
            "message": "Module not currently loaded",
        }

    patched = False
    for pkg in target.get("fixed_in", [])[:3]:
        pkg_name = pkg.split("-")[0] if "-" in pkg else pkg
        rpm_check = await ssh.execute(f"rpm -q {pkg_name} 2>/dev/null")
        if rpm_check.success:
            patched = True
            break

    return {
        "cve_id": cve_id,
        "module_name": module_name,
        "module_loaded": True,
        "patched": patched,
        "safe_to_remove": patched,
        "remove_command": f"semodule -r {module_name}",
        "message": (
            f"Patch applied — safe to remove containment module '{module_name}'"
            if patched
            else f"Patch NOT yet applied — removing '{module_name}' "
            "would re-expose the vulnerability"
        ),
    }


def _generate_containment_options(
    cve_id: str,
    source_type: str,
    gaps: list[dict],
    strategy: str,
) -> list[dict]:
    """Generate containment CIL modules for the identified gaps."""
    safe_cve = cve_id.replace("-", "_").lower()
    options = []

    if strategy in ("minimal", "all"):
        deny_rules = []
        for gap in gaps:
            deny_rules.append(
                f"(deny {gap['source']} {gap['target']} "
                f"({gap['tclass']} ({gap['permission']})))"
            )

        module_name = f"emcp_{safe_cve}_minimal"
        cil = "\n".join([f"(block {module_name}", *[f"  {r}" for r in deny_rules], ")"])
        options.append({
            "strategy": "minimal",
            "description": (
                f"Block only the specific permissions needed "
                f"for the exploit chain ({len(gaps)} rules)"
            ),
            "module_name": module_name,
            "cil_content": cil,
            "effectiveness": min(100, len(gaps) * 20),
            "operational_impact": "low — only exploit-specific permissions blocked",
        })

    if strategy in ("network_isolation", "all"):
        net_gaps = [g for g in gaps if g["tclass"] in ("tcp_socket", "udp_socket")]
        if net_gaps:
            deny_rules = []
            for gap in net_gaps:
                deny_rules.append(
                    f"(deny {gap['source']} {gap['target']} "
                    f"({gap['tclass']} ({gap['permission']})))"
                )
            module_name = f"emcp_{safe_cve}_netiso"
            cil = "\n".join([f"(block {module_name}", *[f"  {r}" for r in deny_rules], ")"])
            options.append({
                "strategy": "network_isolation",
                "description": "Block network access used in the exploit chain",
                "module_name": module_name,
                "cil_content": cil,
                "effectiveness": min(100, len(net_gaps) * 30),
                "operational_impact": "medium — network operations may be affected",
            })

    if strategy in ("full_lockdown", "all"):
        deny_rules = []
        for gap in gaps:
            deny_rules.append(
                f"(deny {gap['source']} {gap['target']} "
                f"({gap['tclass']} ({gap['permission']})))"
            )
        deny_rules.append(
            f"(deny {source_type} self (process (execmem execstack)))"
        )

        module_name = f"emcp_{safe_cve}_lockdown"
        cil = "\n".join([f"(block {module_name}", *[f"  {r}" for r in deny_rules], ")"])
        options.append({
            "strategy": "full_lockdown",
            "description": "Block all exploit chain permissions plus memory execution",
            "module_name": module_name,
            "cil_content": cil,
            "effectiveness": min(100, (len(gaps) + 1) * 25),
            "operational_impact": "high — may affect normal service operation",
        })

    if not options:
        module_name = f"emcp_{safe_cve}_minimal"
        cil = f"(block {module_name}\n  ; No specific deny rules generated\n)"
        options.append({
            "strategy": "minimal",
            "description": "No specific containment rules identified",
            "module_name": module_name,
            "cil_content": cil,
            "effectiveness": 0,
            "operational_impact": "none",
        })

    return options


def _cil_to_rule_dicts(cil: str) -> list[dict]:
    """Parse CIL deny rules into dicts for risk scoring."""
    rules = []
    for line in cil.split("\n"):
        line = line.strip()
        if line.startswith("(deny ") or line.startswith("(allow "):
            parts = line.strip("()").split()
            if len(parts) >= 4:
                rules.append({
                    "source": parts[1],
                    "target": parts[2],
                    "permissions": [],
                })
    return rules
