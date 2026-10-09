"""Audit trail for all tool invocations.

Writes JSONL to remote host at /var/lib/enforcement-mcp/audit.jsonl.
Falls back to local logging if remote write fails.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from .models.identity import AuditEntry, CallerIdentity
from .ssh import SSHBackend

logger = logging.getLogger(__name__)

AUDIT_PATH = "/var/lib/enforcement-mcp/audit.jsonl"


async def write_audit_entry(
    ssh: SSHBackend,
    *,
    caller: CallerIdentity,
    tool: str,
    parameters: dict,
    risk_score: int | None = None,
    risk_level: str | None = None,
    result_status: str,
    identity_mode: str,
    authz_decision: str,
) -> AuditEntry:
    entry = AuditEntry(
        timestamp=datetime.now(UTC).isoformat(),
        caller=caller.display_name,
        tool=tool,
        parameters=_sanitize_params(parameters),
        risk_score=risk_score,
        risk_level=risk_level,
        result_status=result_status,
        identity_mode=identity_mode,
        authz_decision=authz_decision,
    )

    line = json.dumps(entry.model_dump())
    escaped = line.replace("'", "'\\''")
    cmd = (
        f"mkdir -p /var/lib/enforcement-mcp && "
        f"echo '{escaped}' >> {AUDIT_PATH}"
    )
    try:
        result = await ssh.execute(cmd, timeout=5)
        if not result.success:
            logger.warning("Audit write failed: %s", result.stderr)
    except Exception:
        logger.warning("Audit write failed, logging locally")

    logger.info(
        "AUDIT: %s called %s [%s] risk=%s status=%s",
        entry.caller,
        entry.tool,
        entry.authz_decision,
        entry.risk_score,
        entry.result_status,
    )
    return entry


def _sanitize_params(params: dict) -> dict:
    sanitized = {}
    for k, v in params.items():
        if k in ("identity_token", "token", "password", "secret"):
            sanitized[k] = "***REDACTED***"
        elif isinstance(v, str) and len(v) > 500:
            sanitized[k] = v[:500] + "...[truncated]"
        else:
            sanitized[k] = v
    return sanitized
