"""fapolicyd management tools (Tier 3 — mutating, risk-gated)."""

from enforcement_mcp.risk import score_fapolicyd_trust
from enforcement_mcp.sanitize import SanitizationError, quote_arg, sanitize_path
from enforcement_mcp.ssh import SSHBackend

FAPOLICYD_NOT_INSTALLED = {
    "error": "fapolicyd_not_installed",
    "message": "fapolicyd is not installed on this host",
}


async def _check_fapolicyd(ssh: SSHBackend) -> bool | dict:
    result = await ssh.execute("rpm -q fapolicyd 2>/dev/null")
    if result.exit_code != 0:
        return FAPOLICYD_NOT_INSTALLED
    return True


async def fapolicyd_trust_add(
    ssh: SSHBackend,
    path: str,
    reason: str = "",
    dry_run: bool = True,
) -> dict:
    """Add a binary to fapolicyd ancillary trust."""
    try:
        path = sanitize_path(path)
    except SanitizationError as e:
        return e.to_dict()

    check = await _check_fapolicyd(ssh)
    if isinstance(check, dict):
        return check

    qpath = quote_arg(path)
    file_check = await ssh.execute(f"test -f {qpath} && echo exists")
    if "exists" not in file_check.stdout:
        return {
            "action": "fapolicyd_trust_add",
            "path": path,
            "status": "file_not_found",
            "message": f"File not found: {path}",
        }

    setuid_check = await ssh.execute(f"test -u {qpath} && echo setuid")
    is_setuid = "setuid" in setuid_check.stdout

    risk = score_fapolicyd_trust(path=path, is_setuid=is_setuid)

    preview = {
        "action": "fapolicyd_trust_add",
        "path": path,
        "reason": reason,
        "is_setuid": is_setuid,
        "commands": [
            f"fapolicyd-cli --file add {qpath}",
            "fapolicyd-cli --update",
        ],
        "risk_assessment": risk,
    }

    if dry_run:
        preview["status"] = "preview"
        return preview

    if risk["risk_level"] == "critical":
        preview["status"] = "blocked"
        preview["reason"] = "Risk level is critical"
        return preview

    add_result = await ssh.execute(f"fapolicyd-cli --file add {qpath}")
    if not add_result.success:
        preview["status"] = "failed"
        preview["error"] = add_result.stderr.strip()
        return preview

    update_result = await ssh.execute("fapolicyd-cli --update")
    if not update_result.success:
        preview["status"] = "failed"
        preview["error"] = f"Trust added but update failed: {update_result.stderr.strip()}"
        return preview

    verify = await ssh.execute(f"fapolicyd-cli --dump-db 2>/dev/null | grep {qpath}")
    preview["status"] = "applied"
    preview["verified_trusted"] = bool(verify.stdout.strip())
    return preview


async def fapolicyd_trust_remove(
    ssh: SSHBackend,
    path: str,
    dry_run: bool = True,
) -> dict:
    """Remove a binary from fapolicyd trust."""
    try:
        path = sanitize_path(path)
    except SanitizationError as e:
        return e.to_dict()

    check = await _check_fapolicyd(ssh)
    if isinstance(check, dict):
        return check

    qpath = quote_arg(path)
    in_db = await ssh.execute(f"fapolicyd-cli --dump-db 2>/dev/null | grep {qpath}")
    if not in_db.stdout.strip():
        return {
            "action": "fapolicyd_trust_remove",
            "path": path,
            "status": "not_in_trust",
            "message": f"'{path}' is not in the trust database",
        }

    preview = {
        "action": "fapolicyd_trust_remove",
        "path": path,
        "commands": [
            f"fapolicyd-cli --file delete {qpath}",
            "fapolicyd-cli --update",
        ],
    }

    if dry_run:
        preview["status"] = "preview"
        preview["warning"] = (
            "Removing trust will cause fapolicyd to block this binary on next execution"
        )
        return preview

    del_result = await ssh.execute(f"fapolicyd-cli --file delete {qpath}")
    if not del_result.success:
        preview["status"] = "failed"
        preview["error"] = del_result.stderr.strip()
        return preview

    await ssh.execute("fapolicyd-cli --update")

    verify = await ssh.execute(f"fapolicyd-cli --dump-db 2>/dev/null | grep {qpath}")
    preview["status"] = "removed"
    preview["verified_removed"] = not bool(verify.stdout.strip())
    return preview
