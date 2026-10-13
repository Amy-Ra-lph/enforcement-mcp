"""FastMCP server setup for enforcement-mcp."""

import logging
from pathlib import Path
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
    generate_playbook,
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
    version="0.5.1",
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
        "All SSH-connected tools accept an optional 'target' parameter to specify "
        "which RHEL host to analyze (e.g. 'webserver01.example.com' or 'root@host:22'). "
        "If target is omitted, the server's default target is used. "
        "Management tools accept an optional identity_token for RBAC enforcement. "
        "When SELinux is disabled or fapolicyd is not installed, tools return clear error objects."
    ),
)

TargetParam = Annotated[
    str | None,
    Field(
        description=(
            "Target RHEL host to analyze. Overrides the default for this call. "
            "Accepts: hostname, user@hostname, hostname:port, user@hostname:port. "
            "Examples: 'webserver01.example.com', 'root@db01.example.com:22'"
        ),
    ),
]

LogFileParam = Annotated[
    str | None,
    Field(
        description=(
            "Path to a local log file containing denial records "
            "(audit.log, ausearch output, SIEM export, etc.). "
            "The file is read and its contents used for offline analysis. "
            "Mutually exclusive with raw_text/raw_avc_text parameters."
        ),
    ),
]

MAX_LOG_FILE_BYTES = 10 * 1024 * 1024  # 10 MB


def _read_log_file(log_file: str) -> str:
    """Read and validate a local log file. Returns file contents."""
    p = Path(log_file).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(f"Log file not found: {log_file}")
    size = p.stat().st_size
    if size > MAX_LOG_FILE_BYTES:
        raise ValueError(
            f"Log file too large ({size / 1024 / 1024:.1f} MB). "
            f"Max: {MAX_LOG_FILE_BYTES / 1024 / 1024:.0f} MB. "
            "Filter the file first (e.g. grep 'avc:  denied' audit.log > denials.txt)."
        )
    if size == 0:
        raise ValueError(f"Log file is empty: {log_file}")
    return p.read_text(encoding="utf-8", errors="replace")


_default_target: str | None = None
_ssh_pool: dict[str, SSHBackend] = {}
_identity_config: IdentityConfig | None = None


def set_default_target(target: str) -> None:
    """Set the default SSH target (called from CLI --target)."""
    global _default_target
    _default_target = target


async def _get_ssh(target: str | None = None) -> SSHBackend:
    """Get SSH connection for a target, with connection pooling.

    Resolution order: explicit target > CLI default > env var.
    """
    resolved = target or _default_target
    pool_key = resolved or "__env__"

    if pool_key in _ssh_pool:
        return _ssh_pool[pool_key]

    config = get_host_config(resolved)
    ssh = SSHBackend(
        host=config.host,
        user=config.user,
        port=config.port,
        key_file=config.key_file,
    )
    await ssh.connect()
    _ssh_pool[pool_key] = ssh
    return ssh


def _get_identity_config() -> IdentityConfig:
    global _identity_config
    if _identity_config is None:
        _identity_config = get_identity_config()
    return _identity_config


async def _verify_and_authorize(
    tool_name: str,
    identity_token: str | None,
    params: dict,
    target: str | None = None,
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
        ssh = await _get_ssh(target)
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
    target: str | None = None,
) -> None:
    cfg = _get_identity_config()
    ssh = await _get_ssh(target)
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
    log_file: LogFileParam = None,
    target: TargetParam = None,
) -> dict:
    """Diagnose why something is blocked. Pass raw_avc_text/raw_fanotify_text, or log_file for offline analysis, or omit all to query a live host via SSH."""
    if log_file and not raw_avc_text and not raw_fanotify_text:
        raw_avc_text = _read_log_file(log_file)
    offline = raw_avc_text is not None or raw_fanotify_text is not None
    ssh = None if offline else await _get_ssh(target)
    return await troubleshoot(
        ssh, symptom=symptom, process=process, path=path,
        raw_avc_text=raw_avc_text, raw_fanotify_text=raw_fanotify_text,
    )


@mcp.tool(name="diagnosis.host_posture")
async def tool_host_posture(
    target: TargetParam = None,
) -> dict:
    """Comprehensive security posture summary — SELinux, fapolicyd, MLS, with a 0-100 score."""
    ssh = await _get_ssh(target)
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
    log_file: LogFileParam = None,
    target: TargetParam = None,
) -> dict:
    """Get SELinux AVC denials. Pass raw_text or log_file for offline analysis, or omit to query a live host via SSH."""
    if log_file and not raw_text:
        raw_text = _read_log_file(log_file)
    ssh = None if raw_text else await _get_ssh(target)
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
    target: TargetParam = None,
) -> dict:
    """Query SELinux allow rules for a source type."""
    ssh = await _get_ssh(target)
    return await policy_query(ssh, source_type=source_type, tclass=tclass, permission=permission)


@mcp.tool(name="diagnosis.boolean_list")
async def tool_boolean_list(
    filter: Annotated[str | None, Field(description="Substring filter, e.g. 'httpd'")] = None,
    target: TargetParam = None,
) -> dict:
    """List SELinux booleans with current state."""
    ssh = await _get_ssh(target)
    return await boolean_list(ssh, filter_str=filter)


@mcp.tool(name="diagnosis.file_context")
async def tool_file_context(
    path: Annotated[str, Field(description="Filesystem path to check, e.g. '/var/www/html'")],
    target: TargetParam = None,
) -> dict:
    """Check expected vs actual SELinux file context. Detects mismatches."""
    ssh = await _get_ssh(target)
    return await file_context(ssh, path=path)


@mcp.tool(name="diagnosis.denial_explain")
async def tool_denial_explain(
    source: Annotated[str, Field(description="Source SELinux type, e.g. 'httpd_t'")],
    target_type: Annotated[str, Field(description="Target SELinux type, e.g. 'user_home_t'")],
    tclass: Annotated[str, Field(description="Object class, e.g. 'file', 'dir'")],
    permission: Annotated[str, Field(description="Permission, e.g. 'read', 'write'")],
    target: TargetParam = None,
) -> dict:
    """Explain why a specific SELinux denial happened."""
    ssh = await _get_ssh(target)
    return await denial_explain(
        ssh, source=source, target=target_type, tclass=tclass, permission=permission
    )


@mcp.tool(name="diagnosis.fapolicyd_status")
async def tool_fapolicyd_status(
    target: TargetParam = None,
) -> dict:
    """Get fapolicyd daemon status, rule count, and trust DB size."""
    ssh = await _get_ssh(target)
    return await fapolicyd_status(ssh)


@mcp.tool(name="diagnosis.fapolicyd_denials")
async def tool_fapolicyd_denials(
    since: Annotated[str, Field(description="Time window, e.g. '1h', '24h', 'recent'")] = "24h",
    raw_text: Annotated[
        str | None,
        Field(description="Raw FANOTIFY denial text (from log aggregator or audit.log). If provided, parses this instead of querying via SSH."),
    ] = None,
    log_file: LogFileParam = None,
    target: TargetParam = None,
) -> dict:
    """Get fapolicyd FANOTIFY denials. Pass raw_text or log_file for offline analysis, or omit to query a live host."""
    if log_file and not raw_text:
        raw_text = _read_log_file(log_file)
    ssh = None if raw_text else await _get_ssh(target)
    return await fapolicyd_denials(ssh, since=since, raw_text=raw_text)


@mcp.tool(name="diagnosis.fapolicyd_trust_check")
async def tool_fapolicyd_trust_check(
    path: Annotated[str, Field(description="Full path to binary, e.g. '/tmp/suspicious_binary'")],
    target: TargetParam = None,
) -> dict:
    """Check whether a specific binary is trusted by fapolicyd."""
    ssh = await _get_ssh(target)
    return await fapolicyd_trust_check(ssh, path=path)


@mcp.tool(name="diagnosis.fapolicyd_rules")
async def tool_fapolicyd_rules(
    target: TargetParam = None,
) -> dict:
    """Get current fapolicyd rule set."""
    ssh = await _get_ssh(target)
    return await fapolicyd_rules(ssh)


@mcp.tool(name="diagnosis.mls_user_mappings")
async def tool_mls_user_mappings(
    target: TargetParam = None,
) -> dict:
    """Get user-to-SELinux-user mappings with MLS/MCS ranges."""
    ssh = await _get_ssh(target)
    return await mls_user_mappings(ssh)


@mcp.tool(name="diagnosis.mls_file_level")
async def tool_mls_file_level(
    path: Annotated[str | None, Field(description="File path to check")] = None,
    pid: Annotated[int | None, Field(description="Process ID to check")] = None,
    target: TargetParam = None,
) -> dict:
    """Get MLS level and categories of a file or process."""
    ssh = await _get_ssh(target)
    return await mls_file_level(ssh, path=path, pid=pid)


@mcp.tool(name="diagnosis.mls_categories")
async def tool_mls_categories(
    target: TargetParam = None,
) -> dict:
    """Get defined MLS sensitivities and categories."""
    ssh = await _get_ssh(target)
    return await mls_categories(ssh)


@mcp.tool(name="diagnosis.parse_denials")
async def tool_parse_denials(
    raw_text: Annotated[
        str | None,
        Field(description="Raw denial text — AVC denials, FANOTIFY events, or mixed. Accepts ausearch output, audit.log lines, or SIEM-exported records."),
    ] = None,
    log_file: LogFileParam = None,
    denial_type: Annotated[
        str,
        Field(description="Type of denials: 'avc', 'fanotify', or 'auto' (tries both)"),
    ] = "auto",
) -> dict:
    """Parse denial text into structured JSON — no SSH needed. Pass raw_text directly or log_file to read from disk. Use with audit.log, ausearch output, SIEM exports, etc."""
    if log_file and not raw_text:
        raw_text = _read_log_file(log_file)
    if not raw_text:
        return {"error": "Either raw_text or log_file is required."}
    return parse_denials(raw_text, denial_type=denial_type)


# --- Phase 2: CVE Exposure + Risk Assessment + Containment ---


@mcp.tool(name="diagnosis.cve_exposure")
async def tool_cve_exposure(
    cve: Annotated[str, Field(description="CVE ID, e.g. 'CVE-2024-6387'")],
    target: TargetParam = None,
) -> dict:
    """Assess current policy effectiveness against a CVE's exploit chain. Maps CVE to ATT&CK techniques and checks which steps SELinux blocks."""
    ssh = await _get_ssh(target)
    return await cve_exposure(ssh, cve_id=cve)


@mcp.tool(name="diagnosis.active_containments")
async def tool_active_containments(
    target: TargetParam = None,
) -> dict:
    """List temporary CVE containment modules currently in effect, with patch status."""
    ssh = await _get_ssh(target)
    return await active_containments(ssh)


@mcp.tool(name="diagnosis.generate_playbook")
async def tool_generate_playbook(
    finding_type: Annotated[
        str,
        Field(description="Type: 'denial', 'file_context', 'fapolicyd_block', 'aide_change'"),
    ],
    source_type: Annotated[
        str | None, Field(description="SELinux source type (denial)")
    ] = None,
    target_type: Annotated[
        str | None, Field(description="SELinux target type (denial)")
    ] = None,
    tclass: Annotated[
        str | None, Field(description="Object class (denial)")
    ] = None,
    permission: Annotated[
        str | None, Field(description="Permission (denial)")
    ] = None,
    path: Annotated[
        str | None, Field(description="File path (any finding type)")
    ] = None,
    expected_type: Annotated[
        str | None, Field(description="Expected SELinux type (file_context)")
    ] = None,
    actual_type: Annotated[
        str | None, Field(description="Actual SELinux type (file_context)")
    ] = None,
    changed_paths: Annotated[
        list[str] | None, Field(description="Changed file paths (aide_change)")
    ] = None,
    action: Annotated[
        str | None, Field(description="'investigate' or 'accept' (aide_change)")
    ] = None,
    target: TargetParam = None,
) -> dict:
    """Generate an Ansible remediation playbook using linux-system-roles. Read-only: returns YAML text with risk assessment, never executes. Ranks fix options from narrowest scope to broadest."""
    ssh = await _get_ssh(target)
    params: dict = {}
    for key, val in [
        ("source_type", source_type), ("target_type", target_type),
        ("tclass", tclass), ("permission", permission), ("path", path),
        ("expected_type", expected_type), ("actual_type", actual_type),
        ("changed_paths", changed_paths), ("action", action),
    ]:
        if val is not None:
            params[key] = val
    return await generate_playbook(ssh, finding_type=finding_type, **params)


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
    target: TargetParam = None,
) -> dict:
    """Pre-change risk assessment. Returns 0-100 risk score with blast radius, reversibility, and alternatives."""
    tool_params = {"change_type": change_type, "name": name, "value": value}
    caller, err = await _verify_and_authorize("manage.assess_risk", identity_token, tool_params, target)
    if err:
        return err
    ssh = await _get_ssh(target)
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
    await _audit_result(caller, "manage.assess_risk", tool_params, result, target)
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
    target: TargetParam = None,
) -> dict:
    """Generate targeted containment options for a CVE. Maps exploit chain, identifies policy gaps, generates CIL modules with risk assessment. Does NOT auto-apply."""
    tool_params = {"cve": cve, "strategy": strategy}
    caller, err = await _verify_and_authorize("manage.cve_contain", identity_token, tool_params, target)
    if err:
        return err
    ssh = await _get_ssh(target)
    result = await cve_contain(ssh, cve_id=cve, strategy=strategy)
    await _audit_result(caller, "manage.cve_contain", tool_params, result, target)
    return result


@mcp.tool(name="manage.containment_expire")
async def tool_containment_expire(
    cve: Annotated[str, Field(description="CVE ID of the containment to check/remove")],
    identity_token: Annotated[
        str | None, Field(description="OAuth JWT or SPIFFE ID for caller identity")
    ] = None,
    target: TargetParam = None,
) -> dict:
    """Check if a CVE containment module can be safely removed (patch applied). Returns removal command if safe."""
    tool_params = {"cve": cve}
    caller, err = await _verify_and_authorize(
        "manage.containment_expire", identity_token, tool_params, target
    )
    if err:
        return err
    ssh = await _get_ssh(target)
    result = await containment_expire(ssh, cve_id=cve)
    await _audit_result(caller, "manage.containment_expire", tool_params, result, target)
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
    target: TargetParam = None,
) -> dict:
    """Toggle an SELinux boolean. Returns risk assessment and preview. Set dry_run=false to apply."""
    tool_params = {"name": name, "value": value, "persistent": persistent, "dry_run": dry_run}
    caller, err = await _verify_and_authorize("manage.set_boolean", identity_token, tool_params, target)
    if err:
        return err
    ssh = await _get_ssh(target)
    result = await set_boolean(ssh, name=name, value=value, persistent=persistent, dry_run=dry_run)
    await _audit_result(caller, "manage.set_boolean", tool_params, result, target)
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
    target: TargetParam = None,
) -> dict:
    """Generate a CIL module from recent AVC denials. Compares to boolean alternatives. Does NOT auto-load."""
    tool_params = {"name": name, "from_denials": from_denials, "source_type": source_type}
    caller, err = await _verify_and_authorize("manage.generate_module", identity_token, tool_params, target)
    if err:
        return err
    ssh = await _get_ssh(target)
    result = await generate_module(
        ssh, name=name, from_denials=from_denials, source_type=source_type
    )
    await _audit_result(caller, "manage.generate_module", tool_params, result, target)
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
    target: TargetParam = None,
) -> dict:
    """Load a CIL policy module into the running SELinux policy. Set dry_run=false to apply."""
    tool_params = {"name": name, "dry_run": dry_run}
    caller, err = await _verify_and_authorize("manage.load_module", identity_token, tool_params, target)
    if err:
        return err
    ssh = await _get_ssh(target)
    result = await load_module(ssh, name=name, cil=cil, dry_run=dry_run)
    await _audit_result(caller, "manage.load_module", tool_params, result, target)
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
    target: TargetParam = None,
) -> dict:
    """Remove a loaded SELinux policy module. Set dry_run=false to apply."""
    tool_params = {"name": name, "dry_run": dry_run}
    caller, err = await _verify_and_authorize("manage.remove_module", identity_token, tool_params, target)
    if err:
        return err
    ssh = await _get_ssh(target)
    result = await remove_module(ssh, name=name, dry_run=dry_run)
    await _audit_result(caller, "manage.remove_module", tool_params, result, target)
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
    target: TargetParam = None,
) -> dict:
    """Add a persistent file context rule and relabel. Set dry_run=false to apply."""
    tool_params = {"path": path, "context_type": context_type, "dry_run": dry_run}
    caller, err = await _verify_and_authorize(
        "manage.set_file_context", identity_token, tool_params, target
    )
    if err:
        return err
    ssh = await _get_ssh(target)
    result = await set_file_context(ssh, path=path, context_type=context_type, dry_run=dry_run)
    await _audit_result(caller, "manage.set_file_context", tool_params, result, target)
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
    target: TargetParam = None,
) -> dict:
    """Add a binary to fapolicyd ancillary trust. Checks setuid, location risk. Set dry_run=false to apply."""
    tool_params = {"path": path, "reason": reason, "dry_run": dry_run}
    caller, err = await _verify_and_authorize(
        "manage.fapolicyd_trust_add", identity_token, tool_params, target
    )
    if err:
        return err
    ssh = await _get_ssh(target)
    result = await fapolicyd_trust_add(ssh, path=path, reason=reason, dry_run=dry_run)
    await _audit_result(caller, "manage.fapolicyd_trust_add", tool_params, result, target)
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
    target: TargetParam = None,
) -> dict:
    """Remove a binary from fapolicyd trust. Set dry_run=false to apply."""
    tool_params = {"path": path, "dry_run": dry_run}
    caller, err = await _verify_and_authorize(
        "manage.fapolicyd_trust_remove", identity_token, tool_params, target
    )
    if err:
        return err
    ssh = await _get_ssh(target)
    result = await fapolicyd_trust_remove(ssh, path=path, dry_run=dry_run)
    await _audit_result(caller, "manage.fapolicyd_trust_remove", tool_params, result, target)
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
    target: TargetParam = None,
) -> dict:
    """Assign MLS categories to files. Set dry_run=false to apply."""
    tool_params = {
        "path": path,
        "categories": categories,
        "recursive": recursive,
        "dry_run": dry_run,
    }
    caller, err = await _verify_and_authorize(
        "manage.mls_assign_category", identity_token, tool_params, target
    )
    if err:
        return err
    ssh = await _get_ssh(target)
    result = await mls_assign_category(
        ssh, path=path, categories=categories, recursive=recursive, dry_run=dry_run
    )
    await _audit_result(caller, "manage.mls_assign_category", tool_params, result, target)
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
    target: TargetParam = None,
) -> dict:
    """Modify a user's MLS range. Hard-blocks root range restriction. Set dry_run=false to apply."""
    tool_params = {"login": login, "range_spec": range_spec, "dry_run": dry_run}
    caller, err = await _verify_and_authorize(
        "manage.mls_set_user_range", identity_token, tool_params, target
    )
    if err:
        return err
    ssh = await _get_ssh(target)
    result = await mls_set_user_range(ssh, login=login, range_spec=range_spec, dry_run=dry_run)
    await _audit_result(caller, "manage.mls_set_user_range", tool_params, result, target)
    return result
