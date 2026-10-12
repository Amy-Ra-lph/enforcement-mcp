"""AIDE file integrity monitoring tools."""

from __future__ import annotations

from ..parsers.aide_cli import parse_aide_check, parse_aide_config
from ..ssh import SSHBackend


async def _check_aide_installed(ssh: SSHBackend) -> bool:
    result = await ssh.execute("rpm -q aide 2>/dev/null")
    return result.exit_code == 0


AIDE_NOT_INSTALLED_ERROR = {
    "error": "aide_not_installed",
    "message": "AIDE is not installed on this host. Install with: dnf install -y aide",
}


async def aide_check(ssh: SSHBackend) -> dict:
    """Run AIDE integrity check and return structured report.

    Returns added/removed/changed files with attribute details.
    Exit code 0 = no changes, non-zero with output = changes detected.
    """
    if not await _check_aide_installed(ssh):
        return AIDE_NOT_INSTALLED_ERROR

    db_check = await ssh.execute(
        "test -f /var/lib/aide/aide.db.gz || test -f /var/lib/aide/aide.db"
    )
    if db_check.exit_code != 0:
        return {
            "error": "aide_no_database",
            "message": "AIDE database not initialized. Run aide_init_db first.",
        }

    result = await ssh.execute("timeout 120 aide --check 2>/dev/null", timeout=130)
    report = parse_aide_check(result.stdout)
    return report.model_dump()


async def aide_report(ssh: SSHBackend, detail: bool = False) -> dict:
    """Get a summary of the last AIDE check, optionally with per-file detail."""
    if not await _check_aide_installed(ssh):
        return AIDE_NOT_INSTALLED_ERROR

    flag = "--verbose=20" if detail else ""
    result = await ssh.execute(f"timeout 120 aide --check {flag} 2>/dev/null", timeout=130)
    report = parse_aide_check(result.stdout)
    data = report.model_dump()
    if not detail:
        data.pop("changes", None)
    return data


async def aide_config(ssh: SSHBackend) -> dict:
    """Read and parse current AIDE configuration."""
    if not await _check_aide_installed(ssh):
        return AIDE_NOT_INSTALLED_ERROR

    result = await ssh.execute("cat /etc/aide.conf 2>/dev/null")
    if result.exit_code != 0 or not result.stdout.strip():
        return {"error": "aide_no_config", "message": "Cannot read /etc/aide.conf"}
    config = parse_aide_config(result.stdout)
    return config.model_dump()


# --- Management tools ---


async def aide_init_db(ssh: SSHBackend, dry_run: bool = True) -> dict:
    """Initialize the AIDE database.

    This creates the baseline snapshot. Must be run on a known-good system.
    """
    if not await _check_aide_installed(ssh):
        return AIDE_NOT_INSTALLED_ERROR

    if dry_run:
        return {
            "action": "aide_init_db",
            "dry_run": True,
            "command": "aide --init && cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz",
            "warning": "This creates a new baseline. Only run on a known-good system state.",
        }

    result = await ssh.execute("timeout 300 aide --init 2>&1", timeout=310)
    if result.exit_code != 0:
        return {"error": "aide_init_failed", "stderr": result.stderr, "stdout": result.stdout}

    cp_result = await ssh.execute("cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz")
    if cp_result.exit_code != 0:
        return {
            "error": "aide_db_copy_failed",
            "message": "Init succeeded but database copy failed",
        }

    return {"status": "initialized", "database": "/var/lib/aide/aide.db.gz"}


async def aide_update_db(ssh: SSHBackend, dry_run: bool = True) -> dict:
    """Update the AIDE database after known-good changes.

    Creates new database incorporating current system state.
    """
    if not await _check_aide_installed(ssh):
        return AIDE_NOT_INSTALLED_ERROR

    if dry_run:
        return {
            "action": "aide_update_db",
            "dry_run": True,
            "command": "aide --update && cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz",
            "warning": (
                "This updates the baseline."
                " Verify all current changes are legitimate first."
            ),
        }

    result = await ssh.execute("timeout 300 aide --update 2>&1", timeout=310)
    if result.exit_code not in (0, 1, 2, 3, 4, 5, 6, 7):
        return {"error": "aide_update_failed", "stderr": result.stderr}

    report = parse_aide_check(result.stdout)

    cp_result = await ssh.execute("cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz")
    if cp_result.exit_code != 0:
        return {
            "error": "aide_db_copy_failed",
            "message": "Update succeeded but database copy failed",
        }

    return {
        "status": "updated",
        "database": "/var/lib/aide/aide.db.gz",
        "changes_incorporated": report.model_dump(),
    }
