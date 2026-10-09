"""FastMCP server setup for enforcement-mcp."""

import logging
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from .audit import write_audit_entry
from .authz import check_authorization
from .config import IdentityConfig, get_host_config, get_identity_config
from .identity import IdentityVerificationError, anonymous_identity, verify_identity
from .models.identity import CallerIdentity
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
    parse_denials,
    policy_query,
    remove_module,
    set_boolean,
    set_file_context,
    troubleshoot,
)

logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="enforcement-mcp",
    version="0.4.0",
    instructions=(
        "SELinux, fapolicyd, and MLS policy intelligence for RHEL systems. "
        "Use diagnosis.troubleshoot as the primary entry point when something is blocked. "
        "Use diagnosis.host_posture for a comprehensive security overview. "
        "Use diagnosis.cve_exposure to assess policy against a specific CVE. "
        "Use manage.assess_risk before any policy change to understand impact. "
        "diagnosis.parse_denials, avc_denials(raw_text=), fapolicyd_denials(raw_text=), "
        "and troubleshoot(raw_avc_text=/raw_fanotify_text=) support offline analysis "
        "from log aggregators without SSH. "
        "All tools return structured JSON. "
        "Management tools accept an optional identity_token for RBAC enforcement. "
        "When SELinux is disabled or fapolicyd is not installed, tools return clear error objects."
    ),
)

_ssh: SSHBackend | None = None
_identity_config: IdentityConfig | None = None


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


def _get_identity_config() -> IdentityConfig:
    global _identity_config
    if _identity_config is None:
        _identity_config = get_identity_config()
    return _identity_config


async def _verify_and_authorize(
    tool_name: str,
    identity_token: str | None,
    params: dict,
) -> tuple[CallerIdentity, dict | None]:
    cfg = _get_identity_config()
    try:
        caller = await verify_identity(
            identity_token,
            mode=cfg.mode,
            oauth_issuer=cfg.oauth_issuer,
            oauth_audience=cfg.oauth_audience,
            oauth_jwks_uri=cfg.oauth_jwks_uri,
            spiffe_trust_domain=cfg.spiffe_trust_domain,
        )
    except IdentityVerificationError as e:
        return anonymous_identity(), {
            "error": "identity_verification_failed",
            "detail": str(e),
        }

    authz = check_authorization(caller, tool_name, cfg.authz_policy)
    if not authz["authorized"]:
        ssh = await _get_ssh()
        await write_audit_entry(
            ssh,
            caller=caller,
            tool=tool_name,
            parameters=params,
            result_status="denied",
            identity_mode=cfg.mode.value,
            authz_decision="denied",
        )
        return caller, {
            "error": "authorization_denied",
            "detail": authz.get("reason", "Access denied"),
            "caller": authz.get("caller"),
            "required_roles": authz.get("required_roles"),
        }

    return caller, None


async def _audit_result(
    caller: CallerIdentity,
    tool_name: str,
    params: dict,
    result: dict,
) -> None:
    cfg = _get_identity_config()
    ssh = await _get_ssh()
    risk_score = result.get("risk_assessment", {}).get("risk_score") or result.get("risk_score")
    risk_level = result.get("risk_assessment", {}).get("risk_level") or result.get("risk_level")
    status = result.get("status", result.get("error", "success"))
    await write_audit_entry(
        ssh,
        caller=caller,
        tool=tool_name,
        parameters=params,
        risk_score=risk_score,
        risk_level=risk_level,
        result_status=str(status),
        identity_mode=cfg.mode.value,
        authz_decision="authorized",
    )


# --- Diagnosis Tier (no root, read-only) ---


@mcp.tool(name="diagnosis.troubleshoot")
async def tool_troubleshoot(
    symptom: Annotated[
        str, Field(description="What is happening? e.g. 'httpd cannot serve files from /home'")
    ],
    process: Annotated[str | None, Field(description="Process name, e.g. 'httpd'")] = None,
    path: Annotated[str | None, Field(description="Filesystem path involved")] = None,
    raw_avc_text: Annotated[
        str | None,
        Field(description="Raw AVC denial text for offline analysis (from log aggregator, SIEM, or audit.log)"),
    ] = None,
    raw_fanotify_text: Annotated[
        str | None,
        Field(description="Raw FANOTIFY denial text for offline analysis (from log aggregator or audit.log)"),
    ] = None,
) -> dict:
    """Diagnose why something is blocked. Pass raw_avc_text/raw_fanotify_text for offline analysis from log aggregators, or omit to query a live host via SSH."""
    offline = raw_avc_text is not None or raw_fanotify_text is not None
    ssh = None if offline else await _get_ssh()
    return await troubleshoot(
        ssh, symptom=symptom, process=process, path=path,
        raw_avc_text=raw_avc_text, raw_fanotify_text=raw_fanotify_text,
    )


@mcp.tool(name="diagnosis.host_posture")
async def tool_host_posture() -> dict:
    """Comprehensive security posture summary — SELinux, fapolicyd, MLS, with a 0-100 score."""
    ssh = await _get_ssh()
    return await host_posture(ssh)


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
        Field(description="Raw AVC denial text (from log aggregator, SIEM, or audit.log). If provided, parses this instead of querying via SSH."),
    ] = None,
) -> dict:
    """Get SELinux AVC denials. Pass raw_text for offline analysis from log aggregators, or omit to query a live host via SSH."""
    ssh = None if raw_text else await _get_ssh()
    return await avc_denials(ssh, since=since, source_type=source_type, raw_text=raw_text)


@mcp.tool(name="diagnosis.policy_query")
async def tool_policy_query(
    source_type: Annotated[str, Field(description="SELinux type to query, e.g. 'httpd_t'")],
    tclass: Annotated[
        str | None, Field(description="Object class filter, e.g. 'file', 'tcp_socket'")
    ] = None,
    permission: Annotated[
        str | None, Field(description="Permission filter, e.g. 'read', 'name_connect'")
    ] = None,
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
    return await denial_explain(
        ssh, source=source, target=target, tclass=tclass, permission=permission
    )


@mcp.tool(name="diagnosis.fapolicyd_status")
async def tool_fapolicyd_status() -> dict:
    """Get fapolicyd daemon status, rule count, and trust DB size."""
    ssh = await _get_ssh()
    return await fapolicyd_status(ssh)


@mcp.tool(name="diagnosis.fapolicyd_denials")
async def tool_fapolicyd_denials(
    since: Annotated[str, Field(description="Time window, e.g. '1h', '24h', 'recent'")] = "24h",
    raw_text: Annotated[
        str | None,
        Field(description="Raw FANOTIFY denial text (from log aggregator or audit.log). If provided, parses this instead of querying via SSH."),
    ] = None,
) -> dict:
    """Get fapolicyd FANOTIFY denials. Pass raw_text for offline analysis, or omit to query a live host."""
    ssh = None if raw_text else await _get_ssh()
    return await fapolicyd_denials(ssh, since=since, raw_text=raw_text)


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


@mcp.tool(name="diagnosis.parse_denials")
async def tool_parse_denials(
    raw_text: Annotated[
        str,
        Field(description="Raw denial text — AVC denials, FANOTIFY events, or mixed. Accepts ausearch output, audit.log lines, or SIEM-exported records."),
    ],
    denial_type: Annotated[
        str,
        Field(description="Type of denials: 'avc', 'fanotify', or 'auto' (tries both)"),
    ] = "auto",
) -> dict:
    """Parse raw denial text into structured JSON — no SSH needed. Use with log aggregator output (Splunk, ELK, Loki, etc.) or raw audit.log content. Returns parsed denials with summary statistics."""
    return parse_denials(raw_text, denial_type=denial_type)


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
    change_type: Annotated[
        str, Field(description="Type of change: 'boolean', 'module', or 'fapolicyd_trust'")
    ],
    name: Annotated[str | None, Field(description="Boolean name or module name")] = None,
    value: Annotated[
        bool | None, Field(description="New boolean value (for boolean changes)")
    ] = None,
    cil: Annotated[str | None, Field(description="CIL content (for module changes)")] = None,
    path: Annotated[
        str | None, Field(description="Binary path (for fapolicyd_trust changes)")
    ] = None,
    is_setuid: Annotated[bool, Field(description="Whether the binary is setuid")] = False,
    is_containment: Annotated[
        bool, Field(description="Whether this is a CVE containment module")
    ] = False,
    identity_token: Annotated[
        str | None, Field(description="OAuth JWT or SPIFFE ID for caller identity")
    ] = None,
) -> dict:
    """Pre-change risk assessment. Returns 0-100 risk score with blast radius, reversibility, and alternatives."""
    tool_params = {"change_type": change_type, "name": name, "value": value}
    caller, err = await _verify_and_authorize("manage.assess_risk", identity_token, tool_params)
    if err:
        return err
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
    result = await assess_risk(ssh, change_type=change_type, **params)
    await _audit_result(caller, "manage.assess_risk", tool_params, result)
    return result


@mcp.tool(name="manage.cve_contain")
async def tool_cve_contain(
    cve: Annotated[str, Field(description="CVE ID, e.g. 'CVE-2024-6387'")],
    strategy: Annotated[
        str,
        Field(
            description="Containment strategy: 'minimal', 'network_isolation', 'full_lockdown', or 'all' to see all options"
        ),
    ] = "all",
    identity_token: Annotated[
        str | None, Field(description="OAuth JWT or SPIFFE ID for caller identity")
    ] = None,
) -> dict:
    """Generate targeted containment options for a CVE. Maps exploit chain, identifies policy gaps, generates CIL modules with risk assessment. Does NOT auto-apply."""
    tool_params = {"cve": cve, "strategy": strategy}
    caller, err = await _verify_and_authorize("manage.cve_contain", identity_token, tool_params)
    if err:
        return err
    ssh = await _get_ssh()
    result = await cve_contain(ssh, cve_id=cve, strategy=strategy)
    await _audit_result(caller, "manage.cve_contain", tool_params, result)
    return result


@mcp.tool(name="manage.containment_expire")
async def tool_containment_expire(
    cve: Annotated[str, Field(description="CVE ID of the containment to check/remove")],
    identity_token: Annotated[
        str | None, Field(description="OAuth JWT or SPIFFE ID for caller identity")
    ] = None,
) -> dict:
    """Check if a CVE containment module can be safely removed (patch applied). Returns removal command if safe."""
    tool_params = {"cve": cve}
    caller, err = await _verify_and_authorize(
        "manage.containment_expire", identity_token, tool_params
    )
    if err:
        return err
    ssh = await _get_ssh()
    result = await containment_expire(ssh, cve_id=cve)
    await _audit_result(caller, "manage.containment_expire", tool_params, result)
    return result


# --- Phase 3: Management Tier (mutating, risk-gated) ---


@mcp.tool(name="manage.set_boolean")
async def tool_set_boolean(
    name: Annotated[str, Field(description="SELinux boolean name, e.g. 'httpd_enable_homedirs'")],
    value: Annotated[bool, Field(description="New value: true to enable, false to disable")],
    persistent: Annotated[bool, Field(description="Persist across reboots (-P flag)")] = True,
    dry_run: Annotated[
        bool, Field(description="Preview only (default). Set false to apply.")
    ] = True,
    identity_token: Annotated[
        str | None, Field(description="OAuth JWT or SPIFFE ID for caller identity")
    ] = None,
) -> dict:
    """Toggle an SELinux boolean. Returns risk assessment and preview. Set dry_run=false to apply."""
    tool_params = {"name": name, "value": value, "persistent": persistent, "dry_run": dry_run}
    caller, err = await _verify_and_authorize("manage.set_boolean", identity_token, tool_params)
    if err:
        return err
    ssh = await _get_ssh()
    result = await set_boolean(ssh, name=name, value=value, persistent=persistent, dry_run=dry_run)
    await _audit_result(caller, "manage.set_boolean", tool_params, result)
    return result


@mcp.tool(name="manage.generate_module")
async def tool_generate_module(
    name: Annotated[str, Field(description="Module name, e.g. 'httpd_homedir_fix'")],
    from_denials: Annotated[
        str, Field(description="Time window for denials, e.g. '1h', '24h'")
    ] = "1h",
    source_type: Annotated[
        str | None, Field(description="Filter by source type, e.g. 'httpd_t'")
    ] = None,
    identity_token: Annotated[
        str | None, Field(description="OAuth JWT or SPIFFE ID for caller identity")
    ] = None,
) -> dict:
    """Generate a CIL module from recent AVC denials. Compares to boolean alternatives. Does NOT auto-load."""
    tool_params = {"name": name, "from_denials": from_denials, "source_type": source_type}
    caller, err = await _verify_and_authorize("manage.generate_module", identity_token, tool_params)
    if err:
        return err
    ssh = await _get_ssh()
    result = await generate_module(
        ssh, name=name, from_denials=from_denials, source_type=source_type
    )
    await _audit_result(caller, "manage.generate_module", tool_params, result)
    return result


@mcp.tool(name="manage.load_module")
async def tool_load_module(
    name: Annotated[str, Field(description="Module name")],
    cil: Annotated[str, Field(description="CIL policy content to load")],
    dry_run: Annotated[
        bool, Field(description="Preview only (default). Set false to apply.")
    ] = True,
    identity_token: Annotated[
        str | None, Field(description="OAuth JWT or SPIFFE ID for caller identity")
    ] = None,
) -> dict:
    """Load a CIL policy module into the running SELinux policy. Set dry_run=false to apply."""
    tool_params = {"name": name, "dry_run": dry_run}
    caller, err = await _verify_and_authorize("manage.load_module", identity_token, tool_params)
    if err:
        return err
    ssh = await _get_ssh()
    result = await load_module(ssh, name=name, cil=cil, dry_run=dry_run)
    await _audit_result(caller, "manage.load_module", tool_params, result)
    return result


@mcp.tool(name="manage.remove_module")
async def tool_remove_module(
    name: Annotated[str, Field(description="Module name to remove")],
    dry_run: Annotated[
        bool, Field(description="Preview only (default). Set false to apply.")
    ] = True,
    identity_token: Annotated[
        str | None, Field(description="OAuth JWT or SPIFFE ID for caller identity")
    ] = None,
) -> dict:
    """Remove a loaded SELinux policy module. Set dry_run=false to apply."""
    tool_params = {"name": name, "dry_run": dry_run}
    caller, err = await _verify_and_authorize("manage.remove_module", identity_token, tool_params)
    if err:
        return err
    ssh = await _get_ssh()
    result = await remove_module(ssh, name=name, dry_run=dry_run)
    await _audit_result(caller, "manage.remove_module", tool_params, result)
    return result


@mcp.tool(name="manage.set_file_context")
async def tool_set_file_context(
    path: Annotated[str, Field(description="Path pattern, e.g. '/home/jsmith/public_html(/.*)?'")],
    context_type: Annotated[
        str, Field(description="Target SELinux type, e.g. 'httpd_sys_content_t'")
    ],
    dry_run: Annotated[
        bool, Field(description="Preview only (default). Set false to apply.")
    ] = True,
    identity_token: Annotated[
        str | None, Field(description="OAuth JWT or SPIFFE ID for caller identity")
    ] = None,
) -> dict:
    """Add a persistent file context rule and relabel. Set dry_run=false to apply."""
    tool_params = {"path": path, "context_type": context_type, "dry_run": dry_run}
    caller, err = await _verify_and_authorize(
        "manage.set_file_context", identity_token, tool_params
    )
    if err:
        return err
    ssh = await _get_ssh()
    result = await set_file_context(ssh, path=path, context_type=context_type, dry_run=dry_run)
    await _audit_result(caller, "manage.set_file_context", tool_params, result)
    return result


@mcp.tool(name="manage.fapolicyd_trust_add")
async def tool_fapolicyd_trust_add(
    path: Annotated[str, Field(description="Full path to binary, e.g. '/opt/myapp/bin/worker'")],
    reason: Annotated[str, Field(description="Why this binary should be trusted")] = "",
    dry_run: Annotated[
        bool, Field(description="Preview only (default). Set false to apply.")
    ] = True,
    identity_token: Annotated[
        str | None, Field(description="OAuth JWT or SPIFFE ID for caller identity")
    ] = None,
) -> dict:
    """Add a binary to fapolicyd ancillary trust. Checks setuid, location risk. Set dry_run=false to apply."""
    tool_params = {"path": path, "reason": reason, "dry_run": dry_run}
    caller, err = await _verify_and_authorize(
        "manage.fapolicyd_trust_add", identity_token, tool_params
    )
    if err:
        return err
    ssh = await _get_ssh()
    result = await fapolicyd_trust_add(ssh, path=path, reason=reason, dry_run=dry_run)
    await _audit_result(caller, "manage.fapolicyd_trust_add", tool_params, result)
    return result


@mcp.tool(name="manage.fapolicyd_trust_remove")
async def tool_fapolicyd_trust_remove(
    path: Annotated[str, Field(description="Full path to binary to remove from trust")],
    dry_run: Annotated[
        bool, Field(description="Preview only (default). Set false to apply.")
    ] = True,
    identity_token: Annotated[
        str | None, Field(description="OAuth JWT or SPIFFE ID for caller identity")
    ] = None,
) -> dict:
    """Remove a binary from fapolicyd trust. Set dry_run=false to apply."""
    tool_params = {"path": path, "dry_run": dry_run}
    caller, err = await _verify_and_authorize(
        "manage.fapolicyd_trust_remove", identity_token, tool_params
    )
    if err:
        return err
    ssh = await _get_ssh()
    result = await fapolicyd_trust_remove(ssh, path=path, dry_run=dry_run)
    await _audit_result(caller, "manage.fapolicyd_trust_remove", tool_params, result)
    return result


@mcp.tool(name="manage.mls_assign_category")
async def tool_mls_assign_category(
    path: Annotated[str, Field(description="File or directory path")],
    categories: Annotated[list[str], Field(description="MLS categories, e.g. ['c5', 'c10']")],
    recursive: Annotated[bool, Field(description="Apply recursively")] = False,
    dry_run: Annotated[
        bool, Field(description="Preview only (default). Set false to apply.")
    ] = True,
    identity_token: Annotated[
        str | None, Field(description="OAuth JWT or SPIFFE ID for caller identity")
    ] = None,
) -> dict:
    """Assign MLS categories to files. Set dry_run=false to apply."""
    tool_params = {
        "path": path,
        "categories": categories,
        "recursive": recursive,
        "dry_run": dry_run,
    }
    caller, err = await _verify_and_authorize(
        "manage.mls_assign_category", identity_token, tool_params
    )
    if err:
        return err
    ssh = await _get_ssh()
    result = await mls_assign_category(
        ssh, path=path, categories=categories, recursive=recursive, dry_run=dry_run
    )
    await _audit_result(caller, "manage.mls_assign_category", tool_params, result)
    return result


@mcp.tool(name="manage.mls_set_user_range")
async def tool_mls_set_user_range(
    login: Annotated[str, Field(description="Login name, e.g. 'contractor'")],
    range_spec: Annotated[str, Field(description="MLS range, e.g. 's0:c5,c10'")],
    dry_run: Annotated[
        bool, Field(description="Preview only (default). Set false to apply.")
    ] = True,
    identity_token: Annotated[
        str | None, Field(description="OAuth JWT or SPIFFE ID for caller identity")
    ] = None,
) -> dict:
    """Modify a user's MLS range. Hard-blocks root range restriction. Set dry_run=false to apply."""
    tool_params = {"login": login, "range_spec": range_spec, "dry_run": dry_run}
    caller, err = await _verify_and_authorize(
        "manage.mls_set_user_range", identity_token, tool_params
    )
    if err:
        return err
    ssh = await _get_ssh()
    result = await mls_set_user_range(ssh, login=login, range_spec=range_spec, dry_run=dry_run)
    await _audit_result(caller, "manage.mls_set_user_range", tool_params, result)
    return result
