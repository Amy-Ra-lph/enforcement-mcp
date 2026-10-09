"""MLS management tools (Tier 3 — mutating, risk-gated)."""

from enforcement_mcp.sanitize import (
    SanitizationError,
    quote_arg,
    sanitize_login,
    sanitize_mls_categories,
    sanitize_mls_range,
    sanitize_path,
)
from enforcement_mcp.ssh import SSHBackend


async def mls_assign_category(
    ssh: SSHBackend,
    path: str,
    categories: list[str],
    recursive: bool = False,
    dry_run: bool = True,
) -> dict:
    """Assign MLS categories to files."""
    if not categories:
        return {
            "action": "mls_assign_category",
            "error": "missing_categories",
            "message": "At least one category required",
        }

    try:
        path = sanitize_path(path)
        categories = sanitize_mls_categories(categories)
    except SanitizationError as e:
        return e.to_dict()

    cat_str = ",".join(categories)
    qpath = quote_arg(path)
    recursive_flag = " -R" if recursive else ""
    cmd = f"chcat{recursive_flag} +{cat_str} {qpath}"

    current = await ssh.execute(f"ls -dZ {qpath} 2>/dev/null")
    current_context = ""
    if current.success and current.stdout.strip():
        current_context = current.stdout.strip().split()[0]

    preview = {
        "action": "mls_assign_category",
        "path": path,
        "categories": categories,
        "recursive": recursive,
        "current_context": current_context,
        "command": cmd,
    }

    if dry_run:
        preview["status"] = "preview"
        return preview

    result = await ssh.execute(cmd)
    if not result.success:
        preview["status"] = "failed"
        preview["error"] = result.stderr.strip()
        return preview

    verify = await ssh.execute(f"ls -dZ {qpath} 2>/dev/null")
    new_context = ""
    if verify.success and verify.stdout.strip():
        new_context = verify.stdout.strip().split()[0]

    preview["status"] = "applied"
    preview["new_context"] = new_context
    return preview


async def mls_set_user_range(
    ssh: SSHBackend,
    login: str,
    range_spec: str,
    dry_run: bool = True,
) -> dict:
    """Modify a user's MLS range mapping."""
    try:
        login = sanitize_login(login)
        if range_spec != "s0-s0:c0.c1023":
            range_spec = sanitize_mls_range(range_spec)
    except SanitizationError as e:
        return e.to_dict()

    if login == "root" and range_spec != "s0-s0:c0.c1023":
        return {
            "action": "mls_set_user_range",
            "login": login,
            "status": "blocked",
            "reason": (
                "Restricting root's MLS range risks lockout. "
                "This is a hard block — not overridable."
            ),
        }

    qlogin = quote_arg(login)
    qrange = quote_arg(range_spec)
    cmd = f"semanage login -m -r {qrange} {qlogin}"

    current = await ssh.execute(f"semanage login -l 2>/dev/null | grep {qlogin}")
    current_range = ""
    if current.success and current.stdout.strip():
        parts = current.stdout.strip().split()
        if len(parts) >= 3:
            current_range = parts[2]

    if not current.stdout.strip():
        return {
            "action": "mls_set_user_range",
            "login": login,
            "status": "not_found",
            "message": f"No login mapping found for '{login}'",
        }

    preview = {
        "action": "mls_set_user_range",
        "login": login,
        "current_range": current_range,
        "new_range": range_spec,
        "command": cmd,
    }

    if dry_run:
        preview["status"] = "preview"
        return preview

    result = await ssh.execute(cmd)
    if not result.success:
        preview["status"] = "failed"
        preview["error"] = result.stderr.strip()
        return preview

    verify = await ssh.execute(f"semanage login -l 2>/dev/null | grep {qlogin}")
    verified_range = ""
    if verify.success and verify.stdout.strip():
        parts = verify.stdout.strip().split()
        if len(parts) >= 3:
            verified_range = parts[2]

    preview["status"] = "applied"
    preview["verified_range"] = verified_range
    return preview
