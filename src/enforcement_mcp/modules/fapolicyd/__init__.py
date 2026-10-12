"""fapolicyd module — file access policy daemon tools."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated

from pydantic import Field

from ...ssh import SSHBackend
from ...tools.fapolicyd import (
    fapolicyd_denials,
    fapolicyd_rules,
    fapolicyd_status,
    fapolicyd_trust_check,
)
from ...tools.manage_fapolicyd import fapolicyd_trust_add, fapolicyd_trust_remove


def register_readonly_tools(mcp, ssh_provider: Callable[[], Awaitable[SSHBackend]]):
    """Register read-only fapolicyd diagnostic tools."""

    @mcp.tool(name="diagnosis.fapolicyd_status")
    async def tool_fapolicyd_status() -> dict:
        """Get fapolicyd daemon status, rule count, and trust DB size."""
        ssh = await ssh_provider()
        return await fapolicyd_status(ssh)

    @mcp.tool(name="diagnosis.fapolicyd_denials")
    async def tool_fapolicyd_denials(
        since: Annotated[str, Field(description="Time window, e.g. '1h', '24h'")] = "24h",
        raw_text: Annotated[
            str | None, Field(description="Raw FANOTIFY text for offline analysis")
        ] = None,
    ) -> dict:
        """Get fapolicyd FANOTIFY denials."""
        ssh = None if raw_text else await ssh_provider()
        return await fapolicyd_denials(ssh, since=since, raw_text=raw_text)

    @mcp.tool(name="diagnosis.fapolicyd_trust_check")
    async def tool_fapolicyd_trust_check(
        path: Annotated[str, Field(description="Full path to binary")],
    ) -> dict:
        """Check whether a binary is trusted by fapolicyd."""
        ssh = await ssh_provider()
        return await fapolicyd_trust_check(ssh, path=path)

    @mcp.tool(name="diagnosis.fapolicyd_rules")
    async def tool_fapolicyd_rules() -> dict:
        """Get current fapolicyd rule set."""
        ssh = await ssh_provider()
        return await fapolicyd_rules(ssh)


def register_management_tools(mcp, ssh_provider, auth_handler=None):
    """Register mutating fapolicyd tools."""

    @mcp.tool(name="manage.fapolicyd_trust_add")
    async def tool_fapolicyd_trust_add(
        path: Annotated[str, Field(description="Full path to binary")],
        reason: Annotated[str, Field(description="Why this binary should be trusted")] = "",
        dry_run: Annotated[bool, Field(description="Preview only. Set false to apply.")] = True,
        identity_token: Annotated[str | None, Field(description="OAuth JWT or SPIFFE ID")] = None,
    ) -> dict:
        """Add a binary to fapolicyd ancillary trust."""
        if auth_handler:
            _, err = await auth_handler(
                "manage.fapolicyd_trust_add", identity_token,
                {"path": path, "dry_run": dry_run},
            )
            if err:
                return err
        ssh = await ssh_provider()
        return await fapolicyd_trust_add(ssh, path=path, reason=reason, dry_run=dry_run)

    @mcp.tool(name="manage.fapolicyd_trust_remove")
    async def tool_fapolicyd_trust_remove(
        path: Annotated[str, Field(description="Full path to binary")],
        dry_run: Annotated[bool, Field(description="Preview only. Set false to apply.")] = True,
        identity_token: Annotated[str | None, Field(description="OAuth JWT or SPIFFE ID")] = None,
    ) -> dict:
        """Remove a binary from fapolicyd trust."""
        if auth_handler:
            _, err = await auth_handler(
                "manage.fapolicyd_trust_remove", identity_token,
                {"path": path, "dry_run": dry_run},
            )
            if err:
                return err
        ssh = await ssh_provider()
        return await fapolicyd_trust_remove(ssh, path=path, dry_run=dry_run)


def register_all(mcp, ssh_provider, auth_handler=None):
    """Register all fapolicyd tools."""
    register_readonly_tools(mcp, ssh_provider)
    register_management_tools(mcp, ssh_provider, auth_handler=auth_handler)
