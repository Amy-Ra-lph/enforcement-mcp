"""SELinux module — read-only diagnostics + management tools.

Read-only tools are safe for linux-mcp or any MCP server.
Management tools are mutating and belong in enforcement-mcp.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated

from pydantic import Field

from ...ssh import SSHBackend
from ...tools.manage_selinux import (
    generate_module,
    load_module,
    remove_module,
    set_boolean,
    set_file_context,
)
from ...tools.selinux import (
    avc_denials,
    boolean_list,
    denial_explain,
    file_context,
    policy_query,
)


def register_readonly_tools(mcp, ssh_provider: Callable[[], Awaitable[SSHBackend]]):
    """Register read-only SELinux diagnostic tools."""

    @mcp.tool(name="diagnosis.avc_denials")
    async def tool_avc_denials(
        since: Annotated[
            str, Field(description="Time window, e.g. '1h', '30m', '24h', 'recent'")
        ] = "24h",
        source_type: Annotated[
            str | None, Field(description="Filter by source SELinux type, e.g. 'httpd_t'")
        ] = None,
        raw_text: Annotated[
            str | None,
            Field(description="Raw AVC text for offline analysis"),
        ] = None,
    ) -> dict:
        """Get SELinux AVC denials. Pass raw_text for offline analysis, or omit for live host."""
        ssh = None if raw_text else await ssh_provider()
        return await avc_denials(ssh, since=since, source_type=source_type, raw_text=raw_text)

    @mcp.tool(name="diagnosis.policy_query")
    async def tool_policy_query(
        source_type: Annotated[
        str, Field(description="SELinux type to query, e.g. 'httpd_t'")
    ],
        tclass: Annotated[
            str | None, Field(description="Object class filter, e.g. 'file'")
        ] = None,
        permission: Annotated[
            str | None, Field(description="Permission filter, e.g. 'read'")
        ] = None,
    ) -> dict:
        """Query SELinux allow rules for a source type."""
        ssh = await ssh_provider()
        return await policy_query(
            ssh, source_type=source_type, tclass=tclass, permission=permission
        )

    @mcp.tool(name="diagnosis.boolean_list")
    async def tool_boolean_list(
        filter: Annotated[str | None, Field(description="Substring filter, e.g. 'httpd'")] = None,
    ) -> dict:
        """List SELinux booleans with current state."""
        ssh = await ssh_provider()
        return await boolean_list(ssh, filter_str=filter)

    @mcp.tool(name="diagnosis.file_context")
    async def tool_file_context(
        path: Annotated[str, Field(description="Filesystem path to check")],
    ) -> dict:
        """Check expected vs actual SELinux file context. Detects mismatches."""
        ssh = await ssh_provider()
        return await file_context(ssh, path=path)

    @mcp.tool(name="diagnosis.denial_explain")
    async def tool_denial_explain(
        source: Annotated[str, Field(description="Source SELinux type, e.g. 'httpd_t'")],
        target: Annotated[str, Field(description="Target SELinux type, e.g. 'user_home_t'")],
        tclass: Annotated[str, Field(description="Object class, e.g. 'file'")],
        permission: Annotated[str, Field(description="Permission, e.g. 'read'")],
    ) -> dict:
        """Explain why a specific SELinux denial happened."""
        ssh = await ssh_provider()
        return await denial_explain(
            ssh, source=source, target=target,
            tclass=tclass, permission=permission,
        )


def register_management_tools(
    mcp,
    ssh_provider: Callable[[], Awaitable[SSHBackend]],
    auth_handler=None,
):
    """Register mutating SELinux management tools.

    Args:
        auth_handler: optional async callable(tool_name, identity_token, params)
                      returning (caller, error_dict_or_None)
    """

    @mcp.tool(name="manage.set_boolean")
    async def tool_set_boolean(
        name: Annotated[str, Field(description="SELinux boolean name")],
        value: Annotated[bool, Field(description="New value")],
        persistent: Annotated[bool, Field(description="Persist across reboots")] = True,
        dry_run: Annotated[bool, Field(description="Preview only. Set false to apply.")] = True,
        identity_token: Annotated[str | None, Field(description="OAuth JWT or SPIFFE ID")] = None,
    ) -> dict:
        """Toggle an SELinux boolean with risk assessment."""
        if auth_handler:
            params = {"name": name, "value": value, "persistent": persistent, "dry_run": dry_run}
            _, err = await auth_handler("manage.set_boolean", identity_token, params)
            if err:
                return err
        ssh = await ssh_provider()
        return await set_boolean(
            ssh, name=name, value=value,
            persistent=persistent, dry_run=dry_run,
        )

    @mcp.tool(name="manage.generate_module")
    async def tool_generate_module(
        name: Annotated[str, Field(description="Module name")],
        from_denials: Annotated[str, Field(description="Time window for denials")] = "1h",
        source_type: Annotated[str | None, Field(description="Filter by source type")] = None,
        identity_token: Annotated[str | None, Field(description="OAuth JWT or SPIFFE ID")] = None,
    ) -> dict:
        """Generate a CIL module from recent AVC denials."""
        if auth_handler:
            params = {"name": name, "from_denials": from_denials, "source_type": source_type}
            _, err = await auth_handler("manage.generate_module", identity_token, params)
            if err:
                return err
        ssh = await ssh_provider()
        return await generate_module(
            ssh, name=name, from_denials=from_denials,
            source_type=source_type,
        )

    @mcp.tool(name="manage.load_module")
    async def tool_load_module(
        name: Annotated[str, Field(description="Module name")],
        cil: Annotated[str, Field(description="CIL policy content")],
        dry_run: Annotated[bool, Field(description="Preview only. Set false to apply.")] = True,
        identity_token: Annotated[str | None, Field(description="OAuth JWT or SPIFFE ID")] = None,
    ) -> dict:
        """Load a CIL policy module into the running SELinux policy."""
        if auth_handler:
            _, err = await auth_handler(
                "manage.load_module", identity_token,
                {"name": name, "dry_run": dry_run},
            )
            if err:
                return err
        ssh = await ssh_provider()
        return await load_module(ssh, name=name, cil=cil, dry_run=dry_run)

    @mcp.tool(name="manage.remove_module")
    async def tool_remove_module(
        name: Annotated[str, Field(description="Module name to remove")],
        dry_run: Annotated[bool, Field(description="Preview only. Set false to apply.")] = True,
        identity_token: Annotated[str | None, Field(description="OAuth JWT or SPIFFE ID")] = None,
    ) -> dict:
        """Remove a loaded SELinux policy module."""
        if auth_handler:
            _, err = await auth_handler(
                "manage.remove_module", identity_token,
                {"name": name, "dry_run": dry_run},
            )
            if err:
                return err
        ssh = await ssh_provider()
        return await remove_module(ssh, name=name, dry_run=dry_run)

    @mcp.tool(name="manage.set_file_context")
    async def tool_set_file_context(
        path: Annotated[str, Field(description="Path pattern")],
        context_type: Annotated[str, Field(description="Target SELinux type")],
        dry_run: Annotated[bool, Field(description="Preview only. Set false to apply.")] = True,
        identity_token: Annotated[str | None, Field(description="OAuth JWT or SPIFFE ID")] = None,
    ) -> dict:
        """Add a persistent file context rule and relabel."""
        if auth_handler:
            _, err = await auth_handler(
                "manage.set_file_context", identity_token,
                {"path": path, "context_type": context_type, "dry_run": dry_run},
            )
            if err:
                return err
        ssh = await ssh_provider()
        return await set_file_context(
            ssh, path=path, context_type=context_type, dry_run=dry_run,
        )


def register_all(mcp, ssh_provider, auth_handler=None):
    """Register all SELinux tools (read-only + management)."""
    register_readonly_tools(mcp, ssh_provider)
    register_management_tools(mcp, ssh_provider, auth_handler=auth_handler)
