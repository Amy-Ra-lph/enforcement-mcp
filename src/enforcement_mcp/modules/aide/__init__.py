"""AIDE file integrity monitoring module.

Read-only tools (aide_check, aide_report, aide_config) are safe for any MCP server.
Management tools (aide_init_db, aide_update_db) modify the AIDE database.
"""

from __future__ import annotations

from typing import Annotated, Callable, Awaitable

from pydantic import Field

from ...tools.aide import (
    aide_check,
    aide_config,
    aide_init_db,
    aide_report,
    aide_update_db,
)
from ...ssh import SSHBackend


def register_readonly_tools(mcp, ssh_provider: Callable[[], Awaitable[SSHBackend]]):
    """Register read-only AIDE tools."""

    @mcp.tool(name="diagnosis.aide_check")
    async def tool_aide_check() -> dict:
        """Run AIDE integrity check — returns added/removed/changed files."""
        ssh = await ssh_provider()
        return await aide_check(ssh)

    @mcp.tool(name="diagnosis.aide_report")
    async def tool_aide_report(
        detail: Annotated[bool, Field(description="Include per-file change details")] = False,
    ) -> dict:
        """Get AIDE integrity report summary, optionally with per-file detail."""
        ssh = await ssh_provider()
        return await aide_report(ssh, detail=detail)

    @mcp.tool(name="diagnosis.aide_config")
    async def tool_aide_config() -> dict:
        """Read and parse current AIDE configuration (/etc/aide.conf)."""
        ssh = await ssh_provider()
        return await aide_config(ssh)


def register_management_tools(mcp, ssh_provider, auth_handler=None):
    """Register mutating AIDE tools."""

    @mcp.tool(name="manage.aide_init_db")
    async def tool_aide_init_db(
        dry_run: Annotated[bool, Field(description="Preview only. Set false to apply.")] = True,
        identity_token: Annotated[str | None, Field(description="OAuth JWT or SPIFFE ID")] = None,
    ) -> dict:
        """Initialize AIDE database baseline. Only run on known-good system state."""
        if auth_handler:
            _, err = await auth_handler("manage.aide_init_db", identity_token, {"dry_run": dry_run})
            if err:
                return err
        ssh = await ssh_provider()
        return await aide_init_db(ssh, dry_run=dry_run)

    @mcp.tool(name="manage.aide_update_db")
    async def tool_aide_update_db(
        dry_run: Annotated[bool, Field(description="Preview only. Set false to apply.")] = True,
        identity_token: Annotated[str | None, Field(description="OAuth JWT or SPIFFE ID")] = None,
    ) -> dict:
        """Update AIDE database after known-good changes."""
        if auth_handler:
            _, err = await auth_handler("manage.aide_update_db", identity_token, {"dry_run": dry_run})
            if err:
                return err
        ssh = await ssh_provider()
        return await aide_update_db(ssh, dry_run=dry_run)


def register_all(mcp, ssh_provider, auth_handler=None):
    """Register all AIDE tools."""
    register_readonly_tools(mcp, ssh_provider)
    register_management_tools(mcp, ssh_provider, auth_handler=auth_handler)
