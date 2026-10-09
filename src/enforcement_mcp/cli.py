"""CLI subcommands: setup and check."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def cmd_setup(target: str | None = None) -> None:
    """Configure MCP client to use enforcement-mcp."""
    target = target or os.environ.get("ENFORCEMENT_MCP_TARGET") or ""

    if not target:
        print("Usage: enforcement-mcp setup <target-host>")
        print("  e.g. enforcement-mcp setup webserver01.example.com")
        sys.exit(1)

    snippet = {
        "command": "uvx",
        "args": ["enforcement-mcp"],
        "env": {"ENFORCEMENT_MCP_TARGET": target},
    }

    clients = _detect_clients()
    if not clients:
        print("No MCP clients detected. Add this to your client config manually:\n")
        print(json.dumps({"enforcement-mcp": snippet}, indent=2))
        return

    for name, path, merge_fn in clients:
        print(f"\n{name}: {path}")
        if path.exists():
            existing = json.loads(path.read_text())
            key_path = merge_fn(existing, snippet)
            if key_path:
                print(f"  enforcement-mcp already configured at {key_path}")
                response = input("  Overwrite? [y/N] ").strip().lower()
                if response != "y":
                    print("  Skipped.")
                    continue
            merge_fn(existing, snippet, write=True)
            path.write_text(json.dumps(existing, indent=2) + "\n")
            print(f"  Written. Target: {target}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            config = merge_fn({}, snippet, write=True)
            path.write_text(json.dumps(config, indent=2) + "\n")
            print(f"  Created. Target: {target}")

    print("\nDone. Restart your MCP client to pick up the new config.")


def _detect_clients() -> list[tuple[str, Path, callable]]:
    """Detect installed MCP clients and return (name, config_path, merge_fn)."""
    home = Path.home()
    clients = []

    # Claude Code — project .mcp.json
    claude_project = Path.cwd() / ".mcp.json"

    if claude_project.exists() or (home / ".claude").is_dir():
        clients.append(("Claude Code (.mcp.json)", claude_project, _merge_flat))

    # Claude Desktop
    claude_desktop = home / ".config" / "claude" / "claude_desktop_config.json"
    if claude_desktop.exists() or (home / ".config" / "claude").is_dir():
        clients.append(("Claude Desktop", claude_desktop, _merge_nested))

    # Cursor
    cursor_project = Path.cwd() / ".cursor" / "mcp.json"
    if cursor_project.exists() or (Path.cwd() / ".cursor").is_dir():
        clients.append(("Cursor", cursor_project, _merge_nested))

    return clients


def _merge_flat(config: dict, snippet: dict, write: bool = False) -> str | None:
    """Merge for flat format (Claude Code .mcp.json): {"enforcement-mcp": {...}}"""
    if "enforcement-mcp" in config and not write:
        return "enforcement-mcp"
    if write:
        config["enforcement-mcp"] = snippet
        return config
    return None


def _merge_nested(config: dict, snippet: dict, write: bool = False) -> str | None:
    """Merge for nested format: {"mcpServers": {"enforcement-mcp": {...}}}"""
    servers = config.get("mcpServers", {})
    if "enforcement-mcp" in servers and not write:
        return "mcpServers.enforcement-mcp"
    if write:
        config.setdefault("mcpServers", {})
        config["mcpServers"]["enforcement-mcp"] = snippet
        return config
    return None


def cmd_check(target: str | None = None) -> None:
    """Check target host prerequisites."""
    import asyncio

    target = target or os.environ.get("ENFORCEMENT_MCP_TARGET") or os.environ.get(
        "ENFORCEMENT_MCP_HOST", ""
    )

    if not target:
        print("Usage: enforcement-mcp check <target-host>")
        print("  e.g. enforcement-mcp check webserver01.example.com")
        sys.exit(1)

    print(f"Checking target: {target}\n")
    asyncio.run(_run_checks(target))


async def _run_checks(target: str) -> None:
    from .ssh import SSHBackend

    checks = [
        ("SSH connectivity", "echo ok", None),
        ("SELinux mode", "getenforce", None),
        ("setools-console", "rpm -q setools-console 2>/dev/null", "dnf install -y setools-console"),
        ("ausearch (audit)", "which ausearch 2>/dev/null", "dnf install -y audit"),
        ("fapolicyd", "rpm -q fapolicyd 2>/dev/null", "dnf install -y fapolicyd (optional)"),
        ("semanage", "which semanage 2>/dev/null", "dnf install -y policycoreutils-python-utils"),
        ("Python version", "python3 --version 2>/dev/null", None),
        ("RHEL version", "cat /etc/redhat-release 2>/dev/null", None),
    ]

    user = os.environ.get("ENFORCEMENT_MCP_USER", "root")
    port = int(os.environ.get("ENFORCEMENT_MCP_PORT", "22"))
    key_file = os.environ.get("ENFORCEMENT_MCP_KEY_FILE")

    ssh = SSHBackend(host=target, user=user, port=port, key_file=key_file)

    try:
        await ssh.connect()
    except Exception as e:
        print("  FAIL  SSH connectivity")
        print(f"        {e}")
        print(f"\n        Check: ssh {user}@{target} -p {port}")
        return

    print(f"  PASS  SSH connectivity ({user}@{target}:{port})\n")

    all_pass = True
    for name, cmd, fix in checks[1:]:
        result = await ssh.execute(cmd)
        output = result.stdout.strip()
        if result.success and output and "not installed" not in output:
            print(f"  PASS  {name}: {output}")
        else:
            if fix:
                print(f"  MISS  {name}")
                print(f"        Fix: {fix}")
                all_pass = False
            else:
                print(f"  INFO  {name}: not found")

    await ssh.close()

    print()
    if all_pass:
        print("All prerequisites met. Ready to use.")
    else:
        print("Some prerequisites missing — install the packages listed above.")
        print("Diagnosis tools work without fapolicyd. setools-console is required.")
