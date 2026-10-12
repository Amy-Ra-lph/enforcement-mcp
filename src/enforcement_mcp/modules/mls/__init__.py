"""MLS (Multi-Level Security) module — sensitivity and category tools."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated

from pydantic import Field

from ...ssh import SSHBackend
from ...tools.manage_mls import mls_assign_category, mls_set_user_range
from ...tools.mls import mls_categories, mls_file_level, mls_user_mappings


def register_readonly_tools(mcp, ssh_provider: Callable[[], Awaitable[SSHBackend]]):
    """Register read-only MLS diagnostic tools."""

    @mcp.tool(name="diagnosis.mls_user_mappings")
    async def tool_mls_user_mappings() -> dict:
        """Get user-to-SELinux-user mappings with MLS/MCS ranges."""
        ssh = await ssh_provider()
        return await mls_user_mappings(ssh)

    @mcp.tool(name="diagnosis.mls_file_level")
    async def tool_mls_file_level(
        path: Annotated[str | None, Field(description="File path to check")] = None,
        pid: Annotated[int | None, Field(description="Process ID to check")] = None,
    ) -> dict:
        """Get MLS level and categories of a file or process."""
        ssh = await ssh_provider()
        return await mls_file_level(ssh, path=path, pid=pid)

    @mcp.tool(name="diagnosis.mls_categories")
    async def tool_mls_categories() -> dict:
        """Get defined MLS sensitivities and categories."""
        ssh = await ssh_provider()
        return await mls_categories(ssh)


def register_management_tools(mcp, ssh_provider, auth_handler=None):
    """Register mutating MLS tools."""

    @mcp.tool(name="manage.mls_assign_category")
    async def tool_mls_assign_category(
        path: Annotated[str, Field(description="File or directory path")],
        categories: Annotated[list[str], Field(description="MLS categories, e.g. ['c5', 'c10']")],
        recursive: Annotated[bool, Field(description="Apply recursively")] = False,
        dry_run: Annotated[bool, Field(description="Preview only. Set false to apply.")] = True,
        identity_token: Annotated[str | None, Field(description="OAuth JWT or SPIFFE ID")] = None,
    ) -> dict:
        """Assign MLS categories to files."""
        if auth_handler:
            params = {
                "path": path, "categories": categories,
                "recursive": recursive, "dry_run": dry_run,
            }
            _, err = await auth_handler("manage.mls_assign_category", identity_token, params)
            if err:
                return err
        ssh = await ssh_provider()
        return await mls_assign_category(
            ssh, path=path, categories=categories,
            recursive=recursive, dry_run=dry_run,
        )

    @mcp.tool(name="manage.mls_set_user_range")
    async def tool_mls_set_user_range(
        login: Annotated[str, Field(description="Login name")],
        range_spec: Annotated[str, Field(description="MLS range, e.g. 's0:c5,c10'")],
        dry_run: Annotated[bool, Field(description="Preview only. Set false to apply.")] = True,
        identity_token: Annotated[str | None, Field(description="OAuth JWT or SPIFFE ID")] = None,
    ) -> dict:
        """Modify a user's MLS range."""
        if auth_handler:
            _, err = await auth_handler(
                "manage.mls_set_user_range", identity_token,
                {"login": login, "range_spec": range_spec, "dry_run": dry_run},
            )
            if err:
                return err
        ssh = await ssh_provider()
        return await mls_set_user_range(
            ssh, login=login, range_spec=range_spec, dry_run=dry_run,
        )


def register_all(mcp, ssh_provider, auth_handler=None):
    """Register all MLS tools."""
    register_readonly_tools(mcp, ssh_provider)
    register_management_tools(mcp, ssh_provider, auth_handler=auth_handler)
