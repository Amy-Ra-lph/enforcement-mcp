"""Risk assessment tool."""

from enforcement_mcp.parsers import parse_getenforce, parse_sesearch_allow
from enforcement_mcp.risk import score_boolean_change, score_fapolicyd_trust, score_module_change
from enforcement_mcp.ssh import SSHBackend


async def assess_risk(
    ssh: SSHBackend,
    change_type: str,
    **params: str | bool | list,
) -> dict:
    """Pre-change risk assessment. Callable directly or as gate before mutations."""
    mode = parse_getenforce((await ssh.execute("getenforce")).stdout)
    if mode == "disabled" and change_type in ("boolean", "module"):
        return {
            "error": "selinux_disabled",
            "message": "SELinux is disabled — risk assessment not applicable",
        }

    match change_type:
        case "boolean":
            return await _assess_boolean(ssh, params)
        case "module":
            return await _assess_module(ssh, params)
        case "fapolicyd_trust":
            return _assess_fapolicyd_trust(params)
        case _:
            return {"error": "unknown_change_type", "change_type": change_type}


async def _assess_boolean(ssh: SSHBackend, params: dict) -> dict:
    name = str(params.get("name", ""))
    new_value = bool(params.get("value", True))

    if not name:
        return {"error": "missing_param", "message": "boolean name required"}

    cmd = f"sesearch --allow -b {name} 2>/dev/null"
    result = await ssh.execute(cmd)
    rules_raw = parse_sesearch_allow(result.stdout)

    domains = list({r["source"] for r in rules_raw})

    return score_boolean_change(
        name=name,
        new_value=new_value,
        rules_unlocked=rules_raw,
        domains_affected=domains,
    )


async def _assess_module(ssh: SSHBackend, params: dict) -> dict:
    name = str(params.get("name", "module"))
    cil = str(params.get("cil", ""))
    is_containment = bool(params.get("is_containment", False))

    rules = _parse_cil_rules(cil)

    return score_module_change(
        name=name,
        cil_rules=rules,
        is_containment=is_containment,
    )


def _assess_fapolicyd_trust(params: dict) -> dict:
    path = str(params.get("path", ""))
    is_setuid = bool(params.get("is_setuid", False))

    if not path:
        return {"error": "missing_param", "message": "path required"}

    return score_fapolicyd_trust(path=path, is_setuid=is_setuid)


def _parse_cil_rules(cil: str) -> list[dict]:
    """Extract allow rules from CIL content for risk scoring."""
    rules = []
    for line in cil.split("\n"):
        line = line.strip()
        if line.startswith("(allow "):
            parts = line.strip("()").split()
            if len(parts) >= 4:
                source = parts[1]
                target = parts[2]
                rest = line.split("(", 2)
                tclass = ""
                perms = []
                if len(rest) >= 3:
                    class_perm = rest[2].rstrip(")")
                    class_parts = class_perm.split("(")
                    if class_parts:
                        tclass = class_parts[0].strip()
                    if len(class_parts) > 1:
                        perms = class_parts[1].strip().rstrip(")").split()

                rules.append({
                    "source": source,
                    "target": target,
                    "tclass": tclass,
                    "permissions": perms,
                })
    return rules
