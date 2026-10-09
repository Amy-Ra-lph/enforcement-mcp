"""FastMCP server setup for enforcement-mcp."""

import logging
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from .config import get_host_config
from .ssh import SSHBackend
from .tools import (
    active_containments,
    assess_risk,
    avc_denials,
    boolean_list,
    containment_expire,
    cve_contain,
    cve_exposure,
    denial_explain,
    fapolicyd_denials,
    fapolicyd_rules,
    fapolicyd_status,
    fapolicyd_trust_add,
    fapolicyd_trust_check,
    fapolicyd_trust_remove,
    file_context,
    generate_module,
    host_posture,
    load_module,
    mls_assign_category,
    mls_categories,
    mls_file_level,
    mls_set_user_range,
    mls_user_mappings,
    policy_query,
    remove_module,
    set_boolean,
    set_file_context,
    troubleshoot,
)

logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="enforcement-mcp",
    version="0.3.0",
    instructions=(
        "SELinux, fapolicyd, and MLS policy intelligence for RHEL systems. "
        "Use diagnosis.troubleshoot as the primary entry point when something is blocked. "
        "Use diagnosis.host_posture for a comprehensive security overview. "
        "Use diagnosis.cve_exposure to assess policy against a specific CVE. "
        "Use manage.assess_risk before any policy change to understand impact. "
        "All tools return structured JSON. "
        "When SELinux is disabled or fapolicyd is not installed, tools return clear error objects."
    ),
)

_ssh: SSHBackend | None = None


async def _get_ssh() -> SSHBackend:
    global _ssh
    if _ssh is None:
        config = get_host_config()
        _ssh = SSHBackend(
            host=config.host,
            user=config.user,
            port=config.port,
            key_file=config.key_file,
        )
        await _ssh.connect()
    return _ssh


# --- Diagnosis Tier (no root, read-only) ---


@mcp.tool(name="diagnosis.troubleshoot")
async def tool_troubleshoot(
    symptom: Annotated[str, Field(description="What is happening? e.g. 'httpd cannot serve files from /home'")],
    process: Annotated[str | None, Field(description="Process name, e.g. 'httpd'")] = None,
    path: Annotated[str | None, Field(description="Filesystem path involved")] = None,
) -> dict:
    """Diagnose why something is blocked. Checks SELinux, fapolicyd, and DAC systematically."""
    ssh = await _get_ssh()
    return await troubleshoot(ssh, symptom=symptom, process=process, path=path)


@mcp.tool(name="diagnosis.host_posture")
async def tool_host_posture() -> dict:
    """Comprehensive security posture summary — SELinux, fapolicyd, MLS, with a 0-100 score."""
    ssh = await _get_ssh()
    return await host_posture(ssh)


@mcp.tool(name="diagnosis.avc_denials")
async def tool_avc_denials(
    since: Annotated[str, Field(description="Time window, e.g. '1h', '30m', '24h', 'recent'")] = "24h",
    source_type: Annotated[str | None, Field(description="Filter by source SELinux type, e.g. 'httpd_t'")] = None,
) -> dict:
    """Get recent SELinux AVC denials, parsed into structured JSON."""
    ssh = await _get_ssh()
    return await avc_denials(ssh, since=since, source_type=source_type)


@mcp.tool(name="diagnosis.policy_query")
async def tool_policy_query(
    source_type: Annotated[str, Field(description="SELinux type to query, e.g. 'httpd_t'")],
    tclass: Annotated[str | None, Field(description="Object class filter, e.g. 'file', 'tcp_socket'")] = None,
    permission: Annotated[str | None, Field(description="Permission filter, e.g. 'read', 'name_connect'")] = None,
) -> dict:
    """Query SELinux allow rules for a source type."""
    ssh = await _get_ssh()
    return await policy_query(ssh, source_type=source_type, tclass=tclass, permission=permission)


@mcp.tool(name="diagnosis.boolean_list")
async def tool_boolean_list(
    filter: Annotated[str | None, Field(description="Substring filter, e.g. 'httpd'")] = None,
) -> dict:
    """List SELinux booleans with current state."""
    ssh = await _get_ssh()
    return await boolean_list(ssh, filter_str=filter)


@mcp.tool(name="diagnosis.file_context")
async def tool_file_context(
    path: Annotated[str, Field(description="Filesystem path to check, e.g. '/var/www/html'")],
) -> dict:
    """Check expected vs actual SELinux file context. Detects mismatches."""
    ssh = await _get_ssh()
    return await file_context(ssh, path=path)


@mcp.tool(name="diagnosis.denial_explain")
async def tool_denial_explain(
    source: Annotated[str, Field(description="Source SELinux type, e.g. 'httpd_t'")],
    target: Annotated[str, Field(description="Target SELinux type, e.g. 'user_home_t'")],
    tclass: Annotated[str, Field(description="Object class, e.g. 'file', 'dir'")],
    permission: Annotated[str, Field(description="Permission, e.g. 'read', 'write'")],
) -> dict:
    """Explain why a specific SELinux denial happened."""
    ssh = await _get_ssh()
    return await denial_explain(ssh, source=source, target=target, tclass=tclass, permission=permission)


@mcp.tool(name="diagnosis.fapolicyd_status")
async def tool_fapolicyd_status() -> dict:
    """Get fapolicyd daemon status, rule count, and trust DB size."""
    ssh = await _get_ssh()
    return await fapolicyd_status(ssh)


@mcp.tool(name="diagnosis.fapolicyd_denials")
async def tool_fapolicyd_denials(
    since: Annotated[str, Field(description="Time window, e.g. '1h', '24h', 'recent'")] = "24h",
) -> dict:
    """Get recent fapolicyd FANOTIFY denials."""
    ssh = await _get_ssh()
    return await fapolicyd_denials(ssh, since=since)


@mcp.tool(name="diagnosis.fapolicyd_trust_check")
async def tool_fapolicyd_trust_check(
    path: Annotated[str, Field(description="Full path to binary, e.g. '/tmp/suspicious_binary'")],
) -> dict:
    """Check whether a specific binary is trusted by fapolicyd."""
    ssh = await _get_ssh()
    return await fapolicyd_trust_check(ssh, path=path)


@mcp.tool(name="diagnosis.fapolicyd_rules")
async def tool_fapolicyd_rules() -> dict:
    """Get current fapolicyd rule set."""
    ssh = await _get_ssh()
    return await fapolicyd_rules(ssh)


@mcp.tool(name="diagnosis.mls_user_mappings")
async def tool_mls_user_mappings() -> dict:
    """Get user-to-SELinux-user mappings with MLS/MCS ranges."""
    ssh = await _get_ssh()
    return await mls_user_mappings(ssh)


@mcp.tool(name="diagnosis.mls_file_level")
async def tool_mls_file_level(
    path: Annotated[str | None, Field(description="File path to check")] = None,
    pid: Annotated[int | None, Field(description="Process ID to check")] = None,
) -> dict:
    """Get MLS level and categories of a file or process."""
    ssh = await _get_ssh()
    return await mls_file_level(ssh, path=path, pid=pid)


@mcp.tool(name="diagnosis.mls_categories")
async def tool_mls_categories() -> dict:
    """Get defined MLS sensitivities and categories."""
    ssh = await _get_ssh()
    return await mls_categories(ssh)


# --- Phase 2: CVE Exposure + Risk Assessment + Containment ---


@mcp.tool(name="diagnosis.cve_exposure")
async def tool_cve_exposure(
    cve: Annotated[str, Field(description="CVE ID, e.g. 'CVE-2024-6387'")],
) -> dict:
    """Assess current policy effectiveness against a CVE's exploit chain. Maps CVE to ATT&CK techniques and checks which steps SELinux blocks."""
    ssh = await _get_ssh()
    return await cve_exposure(ssh, cve_id=cve)


@mcp.tool(name="diagnosis.active_containments")
async def tool_active_containments() -> dict:
    """List temporary CVE containment modules currently in effect, with patch status."""
    ssh = await _get_ssh()
    return await active_containments(ssh)


@mcp.tool(name="manage.assess_risk")
async def tool_assess_risk(
    change_type: Annotated[str, Field(description="Type of change: 'boolean', 'module', or 'fapolicyd_trust'")],
    name: Annotated[str | None, Field(description="Boolean name or module name")] = None,
    value: Annotated[bool | None, Field(description="New boolean value (for boolean changes)")] = None,
    cil: Annotated[str | None, Field(description="CIL content (for module changes)")] = None,
    path: Annotated[str | None, Field(description="Binary path (for fapolicyd_trust changes)")] = None,
    is_setuid: Annotated[bool, Field(description="Whether the binary is setuid")] = False,
    is_containment: Annotated[bool, Field(description="Whether this is a CVE containment module")] = False,
) -> dict:
    """Pre-change risk assessment. Returns 0-100 risk score with blast radius, reversibility, and alternatives."""
    ssh = await _get_ssh()
    params: dict = {}
    if name is not None:
        params["name"] = name
    if value is not None:
        params["value"] = value
    if cil is not None:
        params["cil"] = cil
    if path is not None:
        params["path"] = path
    if is_setuid:
        params["is_setuid"] = is_setuid
    if is_containment:
        params["is_containment"] = is_containment
    return await assess_risk(ssh, change_type=change_type, **params)


@mcp.tool(name="manage.cve_contain")
async def tool_cve_contain(
    cve: Annotated[str, Field(description="CVE ID, e.g. 'CVE-2024-6387'")],
    strategy: Annotated[str, Field(description="Containment strategy: 'minimal', 'network_isolation', 'full_lockdown', or 'all' to see all options")] = "all",
) -> dict:
    """Generate targeted containment options for a CVE. Maps exploit chain, identifies policy gaps, generates CIL modules with risk assessment. Does NOT auto-apply."""
    ssh = await _get_ssh()
    return await cve_contain(ssh, cve_id=cve, strategy=strategy)


@mcp.tool(name="manage.containment_expire")
async def tool_containment_expire(
    cve: Annotated[str, Field(description="CVE ID of the containment to check/remove")],
) -> dict:
    """Check if a CVE containment module can be safely removed (patch applied). Returns removal command if safe."""
    ssh = await _get_ssh()
    return await containment_expire(ssh, cve_id=cve)


# --- Phase 3: Management Tier (mutating, risk-gated) ---


@mcp.tool(name="manage.set_boolean")
async def tool_set_boolean(
    name: Annotated[str, Field(description="SELinux boolean name, e.g. 'httpd_enable_homedirs'")],
    value: Annotated[bool, Field(description="New value: true to enable, false to disable")],
    persistent: Annotated[bool, Field(description="Persist across reboots (-P flag)")] = True,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply.")] = True,
) -> dict:
    """Toggle an SELinux boolean. Returns risk assessment and preview. Set dry_run=false to apply."""
    ssh = await _get_ssh()
    return await set_boolean(ssh, name=name, value=value, persistent=persistent, dry_run=dry_run)


@mcp.tool(name="manage.generate_module")
async def tool_generate_module(
    name: Annotated[str, Field(description="Module name, e.g. 'httpd_homedir_fix'")],
    from_denials: Annotated[str, Field(description="Time window for denials, e.g. '1h', '24h'")] = "1h",
    source_type: Annotated[str | None, Field(description="Filter by source type, e.g. 'httpd_t'")] = None,
) -> dict:
    """Generate a CIL module from recent AVC denials. Compares to boolean alternatives. Does NOT auto-load."""
    ssh = await _get_ssh()
    return await generate_module(ssh, name=name, from_denials=from_denials, source_type=source_type)


@mcp.tool(name="manage.load_module")
async def tool_load_module(
    name: Annotated[str, Field(description="Module name")],
    cil: Annotated[str, Field(description="CIL policy content to load")],
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply.")] = True,
) -> dict:
    """Load a CIL policy module into the running SELinux policy. Set dry_run=false to apply."""
    ssh = await _get_ssh()
    return await load_module(ssh, name=name, cil=cil, dry_run=dry_run)


@mcp.tool(name="manage.remove_module")
async def tool_remove_module(
    name: Annotated[str, Field(description="Module name to remove")],
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply.")] = True,
) -> dict:
    """Remove a loaded SELinux policy module. Set dry_run=false to apply."""
    ssh = await _get_ssh()
    return await remove_module(ssh, name=name, dry_run=dry_run)


@mcp.tool(name="manage.set_file_context")
async def tool_set_file_context(
    path: Annotated[str, Field(description="Path pattern, e.g. '/home/jsmith/public_html(/.*)?'")],
    context_type: Annotated[str, Field(description="Target SELinux type, e.g. 'httpd_sys_content_t'")],
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply.")] = True,
) -> dict:
    """Add a persistent file context rule and relabel. Set dry_run=false to apply."""
    ssh = await _get_ssh()
    return await set_file_context(ssh, path=path, context_type=context_type, dry_run=dry_run)


@mcp.tool(name="manage.fapolicyd_trust_add")
async def tool_fapolicyd_trust_add(
    path: Annotated[str, Field(description="Full path to binary, e.g. '/opt/myapp/bin/worker'")],
    reason: Annotated[str, Field(description="Why this binary should be trusted")] = "",
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply.")] = True,
) -> dict:
    """Add a binary to fapolicyd ancillary trust. Checks setuid, location risk. Set dry_run=false to apply."""
    ssh = await _get_ssh()
    return await fapolicyd_trust_add(ssh, path=path, reason=reason, dry_run=dry_run)


@mcp.tool(name="manage.fapolicyd_trust_remove")
async def tool_fapolicyd_trust_remove(
    path: Annotated[str, Field(description="Full path to binary to remove from trust")],
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply.")] = True,
) -> dict:
    """Remove a binary from fapolicyd trust. Set dry_run=false to apply."""
    ssh = await _get_ssh()
    return await fapolicyd_trust_remove(ssh, path=path, dry_run=dry_run)


@mcp.tool(name="manage.mls_assign_category")
async def tool_mls_assign_category(
    path: Annotated[str, Field(description="File or directory path")],
    categories: Annotated[list[str], Field(description="MLS categories, e.g. ['c5', 'c10']")],
    recursive: Annotated[bool, Field(description="Apply recursively")] = False,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply.")] = True,
) -> dict:
    """Assign MLS categories to files. Set dry_run=false to apply."""
    ssh = await _get_ssh()
    return await mls_assign_category(ssh, path=path, categories=categories, recursive=recursive, dry_run=dry_run)


@mcp.tool(name="manage.mls_set_user_range")
async def tool_mls_set_user_range(
    login: Annotated[str, Field(description="Login name, e.g. 'contractor'")],
    range_spec: Annotated[str, Field(description="MLS range, e.g. 's0:c5,c10'")],
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply.")] = True,
) -> dict:
    """Modify a user's MLS range. Hard-blocks root range restriction. Set dry_run=false to apply."""
    ssh = await _get_ssh()
    return await mls_set_user_range(ssh, login=login, range_spec=range_spec, dry_run=dry_run)
