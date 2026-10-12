"""Parsers for AIDE CLI output."""

from __future__ import annotations

import re

from ..models.aide import AIDEChange, AIDEConfig, AIDEReport


def parse_aide_check(stdout: str) -> AIDEReport:
    """Parse `aide --check` output into structured report."""
    changes: list[AIDEChange] = []
    added = removed = changed = total = 0

    summary_match = re.search(
        r"Added entries:\s*(\d+).*?"
        r"Removed entries:\s*(\d+).*?"
        r"Changed entries:\s*(\d+)",
        stdout,
        re.DOTALL,
    )
    if summary_match:
        added = int(summary_match.group(1))
        removed = int(summary_match.group(2))
        changed = int(summary_match.group(3))

    total_match = re.search(r"Total number of entries:\s*(\d+)", stdout)
    if total_match:
        total = int(total_match.group(1))

    section = ""
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Added entries"):
            section = "added"
            continue
        elif stripped.startswith("Removed entries"):
            section = "removed"
            continue
        elif stripped.startswith("Changed entries"):
            section = "changed"
            continue
        elif stripped.startswith("Detailed information") or stripped.startswith("The attributes of"):
            section = ""
            continue
        elif stripped.startswith("---") or not stripped:
            continue

        if not section:
            continue

        # AIDE 0.19+ format: "f > ...   ..H.... : /etc/hosts"
        colon_match = re.match(r".*:\s+(/\S+)", stripped)
        if colon_match:
            path = colon_match.group(1)
            attrs_str = stripped[:stripped.rfind(":")]
            changes.append(AIDEChange(path=path, change_type=section, attributes={"detail": attrs_str.strip()}))
            continue

        # Older format: path at start of line
        if stripped.startswith("/"):
            path = stripped.split()[0] if " " in stripped else stripped
            changes.append(AIDEChange(path=path, change_type=section, attributes={}))

    return AIDEReport(
        added=added,
        removed=removed,
        changed=changed,
        total_files_checked=total,
        changes=changes,
    )


def parse_aide_config(stdout: str) -> AIDEConfig:
    """Parse /etc/aide.conf into structured config."""
    db_path = ""
    db_out_path = ""
    rules: list[dict] = []
    custom_rules: list[dict] = []

    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.startswith("@@define"):
            continue

        db_match = re.match(r"database\s*=\s*(.+)", stripped, re.IGNORECASE)
        if db_match:
            db_path = db_match.group(1).strip()
            continue

        db_out_match = re.match(r"database_out\s*=\s*(.+)", stripped, re.IGNORECASE)
        if db_out_match:
            db_out_path = db_out_match.group(1).strip()
            continue

        rule_def = re.match(r"(\w+)\s*=\s*(.+)", stripped)
        if rule_def and not stripped.startswith("/"):
            custom_rules.append({"name": rule_def.group(1), "definition": rule_def.group(2).strip()})
            continue

        if stripped.startswith("!"):
            rules.append({"path": stripped, "rule": "exclude"})
            continue

        path_match = re.match(r"([/].+?)\s+(\S+)", stripped)
        if path_match:
            rules.append({"path": path_match.group(1), "rule": path_match.group(2)})

    return AIDEConfig(
        database_path=db_path,
        database_out_path=db_out_path,
        rules=rules,
        custom_rules=custom_rules,
    )
