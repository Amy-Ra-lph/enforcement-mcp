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
    fapolicyd_trust_check,
    file_context,
    host_posture,
    mls_categories,
    mls_file_level,
    mls_user_mappings,
    policy_query,
    troubleshoot,
)

logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="enforcement-mcp",
    version="0.2.0",
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
