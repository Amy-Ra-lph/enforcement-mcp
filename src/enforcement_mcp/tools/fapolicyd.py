"""fapolicyd diagnosis tools."""

from enforcement_mcp.parsers import (
    parse_fanotify_denials,
    parse_fapolicyd_rules,
    parse_time_spec,
)
from enforcement_mcp.sanitize import (
    SanitizationError,
    quote_arg,
    sanitize_path,
)
from enforcement_mcp.ssh import SSHBackend

FAPOLICYD_NOT_INSTALLED_ERROR = {
    "error": "fapolicyd_not_installed",
    "message": "fapolicyd is not installed on this host.",
}


async def _check_fapolicyd_installed(ssh: SSHBackend) -> bool:
    result = await ssh.execute("rpm -q fapolicyd 2>/dev/null")
    return result.exit_code == 0


async def fapolicyd_status(ssh: SSHBackend) -> dict:
    """Get fapolicyd daemon status."""
    if not await _check_fapolicyd_installed(ssh):
        return FAPOLICYD_NOT_INSTALLED_ERROR

    active_result = await ssh.execute("systemctl is-active fapolicyd 2>/dev/null")
    active = active_result.stdout.strip() == "active"

    rules_result = await ssh.execute(
        "cat /etc/fapolicyd/rules.d/*.rules 2>/dev/null | grep -c -v '^#\\|^$'"
    )
    rules = int(rules_result.stdout.strip()) if rules_result.success else 0

    trust_result = await ssh.execute("fapolicyd-cli --list 2>/dev/null | wc -l")
    trust_count = int(trust_result.stdout.strip()) if trust_result.success else 0

    return {
        "active": active,
        "rules": rules,
        "trust_db_entries": trust_count,
        "permissive": False,
    }


async def fapolicyd_denials(
    ssh: SSHBackend | None,
    since: str = "24h",
    raw_text: str | None = None,
) -> dict:
    """Get recent fapolicyd FANOTIFY denials.

    If raw_text is provided, parse from that instead of querying via SSH.
    Enables offline analysis of log aggregator output.
    """
    if raw_text is not None:
        parsed = parse_fanotify_denials(raw_text)
        return {
            "denials": parsed,
            "total": len(parsed),
            "since": "raw_input",
            "source": "raw_text",
        }

    if ssh is None:
        return {"error": "no_connection", "message": "SSH connection required"}
    if not await _check_fapolicyd_installed(ssh):
        return FAPOLICYD_NOT_INSTALLED_ERROR

    ts = parse_time_spec(since)
    result = await ssh.execute(f"ausearch -m FANOTIFY -ts {ts} 2>/dev/null")
    parsed = parse_fanotify_denials(result.stdout)

    return {"denials": parsed, "total": len(parsed), "since": since}


async def fapolicyd_trust_check(ssh: SSHBackend, path: str) -> dict:
    """Check whether a specific binary is trusted by fapolicyd."""
    try:
        path = sanitize_path(path)
    except SanitizationError as e:
        return e.to_dict()

    if not await _check_fapolicyd_installed(ssh):
        return FAPOLICYD_NOT_INSTALLED_ERROR

    db_result = await ssh.execute(
        f"fapolicyd-cli --dump-db 2>/dev/null | grep {quote_arg(path + ' ')}"
    )
    if db_result.success and db_result.stdout.strip():
        parts = db_result.stdout.strip().split("\n")[0].split()
        return {
            "path": path,
            "trusted": True,
            "reason": "in fapolicyd trust database",
            "size": parts[2] if len(parts) > 2 else None,
            "sha256": parts[3] if len(parts) > 3 else None,
        }

    rpm_result = await ssh.execute(f"rpm -qf {quote_arg(path)} 2>/dev/null")
    if rpm_result.success and "not owned" not in rpm_result.stdout:
        return {
            "path": path,
            "trusted": True,
            "reason": f"owned by RPM: {rpm_result.stdout.strip()}",
            "source": "rpm",
        }

    return {
        "path": path,
        "trusted": False,
        "reason": "not in RPM database, not in ancillary trust",
        "would_execute": False,
    }


async def fapolicyd_rules(ssh: SSHBackend) -> dict:
    """Get current fapolicyd rule set."""
    if not await _check_fapolicyd_installed(ssh):
        return FAPOLICYD_NOT_INSTALLED_ERROR

    result = await ssh.execute("cat /etc/fapolicyd/rules.d/*.rules 2>/dev/null | grep -v '^#'")
    parsed = parse_fapolicyd_rules(result.stdout)

    return {"rules": parsed, "total": len(parsed)}
