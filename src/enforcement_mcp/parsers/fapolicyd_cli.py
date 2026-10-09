"""Parse fapolicyd-cli output."""

import re


def parse_fapolicyd_list(raw: str) -> list[dict]:
    """Parse fapolicyd-cli --list output into trust entries."""
    if not raw.strip():
        return []

    results = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("->"):
            continue
        parts = line.split()
        entry: dict = {"path": parts[0]}
        if len(parts) >= 2:
            entry["size"] = parts[1]
        if len(parts) >= 3:
            entry["sha256"] = parts[2]
        results.append(entry)
    return results


def parse_fapolicyd_dumpdb(raw: str) -> list[dict]:
    """Parse fapolicyd-cli --dump-db output into trust DB entries."""
    if not raw.strip():
        return []

    results = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        entry: dict = {"source": parts[0], "path": parts[1]}
        if len(parts) >= 3:
            entry["size"] = parts[2]
        if len(parts) >= 4:
            entry["sha256"] = parts[3]
        results.append(entry)
    return results


def parse_fapolicyd_rules(raw: str) -> list[dict]:
    """Parse fapolicyd rules output into structured rules."""
    if not raw.strip():
        return []

    results = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("->") or line.startswith("#"):
            continue

        rule: dict = {}

        num_match = re.match(r"(\d+)[.\s]+(.+)", line)
        if num_match:
            rule["number"] = int(num_match.group(1))
            remainder = num_match.group(2)
        else:
            remainder = line

        if remainder.startswith("deny"):
            rule["decision"] = "deny"
        elif remainder.startswith("allow"):
            rule["decision"] = "allow"

        rule["raw"] = line
        results.append(rule)

    return results
