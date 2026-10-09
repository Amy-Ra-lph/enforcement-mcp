"""Offline analysis tools — no SSH required.

These tools parse raw text input (e.g., from log aggregators, SIEM exports,
or audit.log files) and return structured JSON. No live system connection needed.
"""

from enforcement_mcp.parsers import parse_avc_denials, parse_fanotify_denials


def parse_denials(raw_text: str, denial_type: str = "auto") -> dict:
    """Parse raw AVC or FANOTIFY denial text into structured JSON.

    Accepts raw ausearch output, audit.log lines, or SIEM-exported denial
    records. Returns structured denials with source/target types, permissions,
    and context information extracted.

    denial_type: 'avc', 'fanotify', or 'auto' (tries both).
    """
    if not raw_text or not raw_text.strip():
        return {
            "avc_denials": [],
            "fanotify_denials": [],
            "total": 0,
            "source": "raw_text",
            "error": "empty_input",
        }

    avc_results: list[dict] = []
    fanotify_results: list[dict] = []

    if denial_type in ("avc", "auto"):
        avc_results = parse_avc_denials(raw_text)

    if denial_type in ("fanotify", "auto"):
        fanotify_results = parse_fanotify_denials(raw_text)

    source_types: dict[str, int] = {}
    for d in avc_results:
        st = d.get("source_type", "unknown")
        source_types[st] = source_types.get(st, 0) + 1

    target_types: dict[str, int] = {}
    for d in avc_results:
        tt = d.get("target_type", "unknown")
        target_types[tt] = target_types.get(tt, 0) + 1

    permissions_seen: dict[str, int] = {}
    for d in avc_results:
        for p in d.get("permissions", []):
            permissions_seen[p] = permissions_seen.get(p, 0) + 1

    return {
        "avc_denials": avc_results,
        "fanotify_denials": fanotify_results,
        "total": len(avc_results) + len(fanotify_results),
        "source": "raw_text",
        "summary": {
            "avc_count": len(avc_results),
            "fanotify_count": len(fanotify_results),
            "top_source_types": dict(sorted(source_types.items(), key=lambda x: -x[1])[:10]),
            "top_target_types": dict(sorted(target_types.items(), key=lambda x: -x[1])[:10]),
            "permissions": dict(sorted(permissions_seen.items(), key=lambda x: -x[1])[:10]),
        },
    }
