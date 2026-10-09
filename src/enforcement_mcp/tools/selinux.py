"""SELinux diagnosis tools."""

from enforcement_mcp.models.selinux import AvcDenial, BooleanInfo, FileContext, PolicyRule
from enforcement_mcp.parsers import (
    parse_avc_denials,
    parse_getenforce,
    parse_getsebool,
    parse_matchpathcon,
    parse_sesearch_allow,
    parse_time_spec,
)
from enforcement_mcp.sanitize import (
    SanitizationError,
    quote_arg,
    sanitize_path,
    sanitize_selinux_class,
    sanitize_selinux_permission,
    sanitize_selinux_type,
)
from enforcement_mcp.ssh import SSHBackend

SELINUX_DISABLED_ERROR = {
    "error": "selinux_disabled",
    "message": "SELinux is disabled on this host. No policy queries possible.",
}


async def check_selinux_enabled(ssh: SSHBackend) -> str:
    """Check SELinux mode. Returns mode string."""
    result = await ssh.execute("getenforce")
    return parse_getenforce(result.stdout)


async def avc_denials(
    ssh: SSHBackend | None,
    since: str = "24h",
    source_type: str | None = None,
    raw_text: str | None = None,
) -> dict:
    """Get recent AVC denials, parsed to structured JSON.

    If raw_text is provided, parse from that instead of querying via SSH.
    Enables offline analysis of log aggregator output.
    """
    if source_type:
        try:
            source_type = sanitize_selinux_type(source_type, "source_type")
        except SanitizationError as e:
            return e.to_dict()

    if raw_text is not None:
        parsed = parse_avc_denials(raw_text)
        denials = [AvcDenial(**d).model_dump() for d in parsed if "source_type" in d]
        if source_type:
            denials = [d for d in denials if d.get("source_type") == source_type]
        return {
            "denials": denials,
            "total": len(denials),
            "since": "raw_input",
            "mode": "offline",
            "source": "raw_text",
        }

    if ssh is None:
        return {"error": "no_connection", "message": "SSH connection required"}
    mode = await check_selinux_enabled(ssh)
    if mode == "disabled":
        return SELINUX_DISABLED_ERROR

    ts = parse_time_spec(since)
    cmd = f"ausearch -m AVC -ts {ts} 2>/dev/null"
    if source_type:
        cmd += f" | grep {quote_arg(f'scontext=.*:{source_type}:')}"

    result = await ssh.execute(cmd)
    parsed = parse_avc_denials(result.stdout)
    denials = [AvcDenial(**d).model_dump() for d in parsed if "source_type" in d]

    return {"denials": denials, "total": len(denials), "since": since, "mode": mode}


async def policy_query(
    ssh: SSHBackend,
    source_type: str,
    tclass: str | None = None,
    permission: str | None = None,
) -> dict:
    """Query allow rules for a source type."""
    try:
        source_type = sanitize_selinux_type(source_type, "source_type")
    except SanitizationError as e:
        return e.to_dict()
    if tclass:
        try:
            tclass = sanitize_selinux_class(tclass, "tclass")
        except SanitizationError as e:
            return e.to_dict()
    if permission:
        try:
            permission = sanitize_selinux_permission(permission, "permission")
        except SanitizationError as e:
            return e.to_dict()

    mode = await check_selinux_enabled(ssh)
    if mode == "disabled":
        return SELINUX_DISABLED_ERROR

    cmd = f"sesearch --allow -s {quote_arg(source_type)}"
    if tclass:
        cmd += f" -c {quote_arg(tclass)}"
    if permission:
        cmd += f" -p {quote_arg(permission)}"
    cmd += " 2>/dev/null"

    result = await ssh.execute(cmd)
    parsed = parse_sesearch_allow(result.stdout)
    rules = [PolicyRule(**r).model_dump() for r in parsed]

    return {"source_type": source_type, "rules": rules, "total": len(rules)}


async def boolean_list(
    ssh: SSHBackend,
    filter_str: str | None = None,
) -> dict:
    """List SELinux booleans with current state."""
    mode = await check_selinux_enabled(ssh)
    if mode == "disabled":
        return SELINUX_DISABLED_ERROR

    result = await ssh.execute("getsebool -a")
    parsed = parse_getsebool(result.stdout)
    booleans = [BooleanInfo(**b).model_dump() for b in parsed]

    if filter_str:
        booleans = [b for b in booleans if filter_str.lower() in b["name"].lower()]

    return {"booleans": booleans, "total": len(booleans), "filter": filter_str}


async def file_context(ssh: SSHBackend, path: str) -> dict:
    """Check expected vs actual SELinux file context."""
    try:
        path = sanitize_path(path)
    except SanitizationError as e:
        return e.to_dict()

    mode = await check_selinux_enabled(ssh)
    if mode == "disabled":
        return SELINUX_DISABLED_ERROR

    expected_result = await ssh.execute(f"matchpathcon {quote_arg(path)}")
    expected = parse_matchpathcon(expected_result.stdout)

    actual_result = await ssh.execute(f"ls -dZ {quote_arg(path)} 2>/dev/null")
    actual_parts = actual_result.stdout.strip().split()
    actual_context = actual_parts[0] if actual_parts else None
    actual_type = actual_context.split(":")[2] if actual_context and ":" in actual_context else None

    fc = FileContext(
        path=path,
        expected_type=expected.get("type"),
        actual_type=actual_type,
        expected_context=expected.get("context"),
        actual_context=actual_context,
    )

    result = fc.model_dump()
    if fc.mismatch:
        result["fix_command"] = f"restorecon -Rv {path}"

    return result


async def denial_explain(
    ssh: SSHBackend,
    source: str,
    target: str,
    tclass: str,
    permission: str,
) -> dict:
    """Explain why a denial happened — boolean, policy gap, or constraint."""
    try:
        source = sanitize_selinux_type(source, "source")
        target = sanitize_selinux_type(target, "target")
        tclass = sanitize_selinux_class(tclass, "tclass")
        permission = sanitize_selinux_permission(permission, "permission")
    except SanitizationError as e:
        return e.to_dict()

    mode = await check_selinux_enabled(ssh)
    if mode == "disabled":
        return SELINUX_DISABLED_ERROR

    cmd = (
        f"sesearch --allow -s {quote_arg(source)} -t {quote_arg(target)} "
        f"-c {quote_arg(tclass)} -p {quote_arg(permission)} -b 2>/dev/null"
    )
    result = await ssh.execute(cmd)
    parsed = parse_sesearch_allow(result.stdout)

    if parsed and parsed[0].get("conditional"):
        boolean_name = parsed[0]["conditional"]
        bool_result = await ssh.execute(f"getsebool {quote_arg(boolean_name)}")
        bool_state = "unknown"
        if "-->" in bool_result.stdout:
            bool_state = bool_result.stdout.split("-->")[1].strip()

        return {
            "cause": "boolean",
            "boolean": boolean_name,
            "current_state": bool_state,
            "fix": f"setsebool -P {boolean_name} on",
            "explanation": (
                f"Access from {source} to {target}:{tclass}:{permission} "
                f"is gated by boolean '{boolean_name}' (currently {bool_state})"
            ),
        }

    cmd2 = (
        f"sesearch --allow -s {quote_arg(source)} -t {quote_arg(target)} "
        f"-c {quote_arg(tclass)} -p {quote_arg(permission)} 2>/dev/null"
    )
    result2 = await ssh.execute(cmd2)
    if not result2.stdout.strip():
        return {
            "cause": "no_rule",
            "explanation": f"No allow rule exists for {source} -> {target}:{tclass}:{permission}",
            "fix_options": [
                {
                    "type": "module",
                    "cil": f"(allow {source} {target} ({tclass} ({permission})))",
                    "scope": "narrow",
                },
            ],
        }

    return {
        "cause": "unknown",
        "explanation": (
            "Rule exists but denial still occurred. May be a constraint or type mismatch."
        ),
    }
