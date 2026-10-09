"""Parse SELinux CLI tool output."""

import re


def parse_getenforce(raw: str) -> str:
    """Parse getenforce output. Returns 'enforcing', 'permissive', or 'disabled'."""
    return raw.strip().lower()


def parse_getsebool(raw: str) -> list[dict]:
    """Parse getsebool -a output into [{name, state}]."""
    results = []
    for line in raw.strip().split("\n"):
        if not line.strip() or "-->" not in line:
            continue
        parts = line.split("-->")
        if len(parts) == 2:
            results.append({
                "name": parts[0].strip(),
                "state": parts[1].strip(),
            })
    return results


def parse_sesearch_allow(raw: str) -> list[dict]:
    """Parse sesearch --allow output into structured rules."""
    results = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line.startswith("allow "):
            continue

        conditional = None
        conditional_state = None
        cond_match = re.search(r"\[\s*(\S+)\s*\]:(\w+)", line)
        if cond_match:
            conditional = cond_match.group(1)
            conditional_state = cond_match.group(2) == "True"

        rule_match = re.match(
            r"allow\s+(\S+)\s+(\S+)\s*:\s*(\S+)\s+\{([^}]+)\}", line
        )
        if not rule_match:
            rule_match = re.match(
                r"allow\s+(\S+)\s+(\S+)\s*:\s*(\S+)\s+(\S+)\s*;", line
            )
            if rule_match:
                rule: dict = {
                    "source": rule_match.group(1),
                    "target": rule_match.group(2),
                    "tclass": rule_match.group(3),
                    "permissions": [rule_match.group(4)],
                }
                if conditional:
                    rule["conditional"] = conditional
                    rule["conditional_state"] = conditional_state
                results.append(rule)
            continue

        rule = {
            "source": rule_match.group(1),
            "target": rule_match.group(2),
            "tclass": rule_match.group(3),
            "permissions": rule_match.group(4).strip().split(),
        }
        if conditional:
            rule["conditional"] = conditional
            rule["conditional_state"] = conditional_state
        results.append(rule)

    return results


def parse_matchpathcon(raw: str) -> dict:
    """Parse matchpathcon output into {path, context, type}."""
    line = raw.strip().split("\n")[0] if raw.strip() else ""
    parts = line.split("\t")
    if len(parts) < 2:
        return {"path": line, "context": None, "type": None}

    path = parts[0].strip()
    context = parts[1].strip()

    if context == "<<none>>":
        return {"path": path, "context": None, "type": None}

    context_parts = context.split(":")
    se_type = context_parts[2] if len(context_parts) >= 3 else None

    return {"path": path, "context": context, "type": se_type}


def parse_semanage_login(raw: str) -> list[dict]:
    """Parse semanage login -l output into [{login, selinux_user, range}]."""
    results = []
    lines = raw.strip().split("\n")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Login Name") or line.startswith("-"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            results.append({
                "login": parts[0],
                "selinux_user": parts[1],
                "range": parts[2],
            })
    return results
