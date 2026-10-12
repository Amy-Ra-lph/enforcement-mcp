"""Parse fapolicyd-cli output."""

import re

from ._hardening import sanitize_parsed_path, validate_input_size


def parse_fapolicyd_list(raw: str) -> list[dict]:
    """Parse fapolicyd-cli --list output into trust entries."""
    validate_input_size(raw, "parse_fapolicyd_list")
    if not raw.strip():
        return []

    results = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("->"):
            continue
        parts = line.split()
        path = sanitize_parsed_path(parts[0])
        if not path:
            continue
        entry: dict = {"path": path}
        if len(parts) >= 2:
            entry["size"] = parts[1]
        if len(parts) >= 3:
            entry["sha256"] = parts[2]
        results.append(entry)
    return results


def parse_fapolicyd_dumpdb(raw: str) -> list[dict]:
    """Parse fapolicyd-cli --dump-db output into trust DB entries."""
    validate_input_size(raw, "parse_fapolicyd_dumpdb")
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
        path = sanitize_parsed_path(parts[1])
        if not path:
            continue
        entry: dict = {"source": parts[0], "path": path}
        if len(parts) >= 3:
            entry["size"] = parts[2]
        if len(parts) >= 4:
            entry["sha256"] = parts[3]
        results.append(entry)
    return results


def parse_fapolicyd_rules(raw: str) -> list[dict]:
    """Parse fapolicyd rules output into structured rules."""
    validate_input_size(raw, "parse_fapolicyd_rules")
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
