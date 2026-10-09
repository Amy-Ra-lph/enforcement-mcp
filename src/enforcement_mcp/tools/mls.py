"""MLS diagnosis tools."""

from enforcement_mcp.parsers import parse_semanage_login
from enforcement_mcp.ssh import SSHBackend


async def mls_user_mappings(ssh: SSHBackend) -> dict:
    """Get user-to-SELinux-user mappings with MLS ranges."""
    result = await ssh.execute("semanage login -l 2>/dev/null")
    parsed = parse_semanage_login(result.stdout)

    return {"mappings": parsed, "total": len(parsed)}


async def mls_file_level(
    ssh: SSHBackend,
    path: str | None = None,
    pid: int | None = None,
) -> dict:
    """Get MLS level of a file or process."""
    if path:
        result = await ssh.execute(f"ls -dZ {path} 2>/dev/null")
    elif pid:
        result = await ssh.execute(f"ps -p {pid} -Z --no-headers 2>/dev/null")
    else:
        return {"error": "invalid_input", "message": "Provide either path or pid"}

    line = result.stdout.strip()
    if not line:
        return {"error": "not_found", "message": f"Target not found: {path or pid}"}

    parts = line.split()
    context = parts[0] if parts else ""
    context_parts = context.split(":")

    target = path or str(pid)

    level = context_parts[3] if len(context_parts) > 3 else ""
    categories: list[str] = []
    if ":" in level:
        level_parts = level.split(":")
        level = level_parts[0]
        if len(level_parts) > 1:
            categories = level_parts[1].split(",")

    return {
        "target": target,
        "user": context_parts[0] if len(context_parts) > 0 else "",
        "role": context_parts[1] if len(context_parts) > 1 else "",
        "type": context_parts[2] if len(context_parts) > 2 else "",
        "level": level,
        "categories": categories,
    }


async def mls_categories(ssh: SSHBackend) -> dict:
    """Get defined MLS categories."""
    sens_result = await ssh.execute("seinfo --sensitivity 2>/dev/null")
    cat_result = await ssh.execute("seinfo --category 2>/dev/null")

    sensitivities = [
        s.strip() for s in sens_result.stdout.strip().split("\n")
        if s.strip() and not s.strip().startswith("Sensitivities:")
    ]
    categories = [
        {"category": c.strip(), "translation": None}
        for c in cat_result.stdout.strip().split("\n")
        if c.strip() and not c.strip().startswith("Categories:")
    ]

    return {
        "sensitivities": sensitivities,
        "categories": categories,
        "total": len(categories),
    }
