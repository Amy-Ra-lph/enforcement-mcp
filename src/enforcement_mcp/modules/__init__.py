"""Pluggable security modules for enforcement-mcp.

Each module (selinux, fapolicyd, mls, aide) exposes:
  register_readonly_tools(mcp, ssh_provider) — safe for any MCP server
  register_management_tools(mcp, ssh_provider) — mutating, enforcement-mcp only
  register_all(mcp, ssh_provider) — both
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import aide, fapolicyd, mls, selinux

_MODULES: dict[str, type] = {}


def discover_modules() -> list[str]:
    """Return names of available modules."""
    return ["selinux", "fapolicyd", "mls", "aide"]


def get_module(name: str):
    """Import and return a module by name."""
    if name == "selinux":
        from . import selinux
        return selinux
    elif name == "fapolicyd":
        from . import fapolicyd
        return fapolicyd
    elif name == "mls":
        from . import mls
        return mls
    elif name == "aide":
        from . import aide
        return aide
    raise ValueError(f"Unknown module: {name}")


def register_all_modules(mcp, ssh_provider, *, readonly_only: bool = False):
    """Register all available modules against an MCP server.

    Args:
        mcp: FastMCP server instance
        ssh_provider: async callable returning SSHBackend
        readonly_only: if True, only register read-only tools
    """
    for name in discover_modules():
        mod = get_module(name)
        if readonly_only:
            mod.register_readonly_tools(mcp, ssh_provider)
        else:
            mod.register_all(mcp, ssh_provider)
