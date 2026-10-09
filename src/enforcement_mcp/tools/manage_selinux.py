"""SELinux management tools (Tier 3 — mutating, risk-gated)."""

from enforcement_mcp.parsers import (
    parse_avc_denials,
    parse_getenforce,
    parse_sesearch_allow,
    parse_time_spec,
)
from enforcement_mcp.risk import score_boolean_change, score_module_change
from enforcement_mcp.sanitize import (
    SanitizationError,
    quote_arg,
    sanitize_cil,
    sanitize_context_path,
    sanitize_identifier,
    sanitize_selinux_type,
)
from enforcement_mcp.ssh import SSHBackend

SELINUX_DISABLED_ERROR = {
    "error": "selinux_disabled",
    "message": "SELinux is disabled — management not possible",
}


async def _check_enforcing(ssh: SSHBackend) -> str | dict:
    mode = parse_getenforce((await ssh.execute("getenforce")).stdout)
    if mode == "disabled":
        return SELINUX_DISABLED_ERROR
    return mode


async def set_boolean(
    ssh: SSHBackend,
    name: str,
    value: bool,
    persistent: bool = True,
    dry_run: bool = True,
) -> dict:
    """Toggle an SELinux boolean with risk assessment."""
    try:
        name = sanitize_identifier(name, "name")
    except SanitizationError as e:
        return e.to_dict()

    check = await _check_enforcing(ssh)
    if isinstance(check, dict):
        return check

    cmd = f"sesearch --allow -b {quote_arg(name)} 2>/dev/null"
    result = await ssh.execute(cmd)
    rules_raw = parse_sesearch_allow(result.stdout)
    domains = list({r["source"] for r in rules_raw})

    risk = score_boolean_change(
        name=name,
        new_value=value,
        rules_unlocked=rules_raw,
        domains_affected=domains,
    )

    val_str = "on" if value else "off"
    persist_flag = " -P" if persistent else ""
    execute_cmd = f"setsebool{persist_flag} {quote_arg(name)} {val_str}"

    preview = {
        "action": "set_boolean",
        "name": name,
        "current_value": None,
        "new_value": val_str,
        "persistent": persistent,
        "command": execute_cmd,
        "rules_affected": len(rules_raw),
        "domains_affected": domains,
        "risk_assessment": risk,
    }

    current = await ssh.execute(f"getsebool {quote_arg(name)}")
    if "-->" in current.stdout:
        preview["current_value"] = current.stdout.split("-->")[1].strip()

    if dry_run:
        preview["status"] = "preview"
        return preview

    if risk["risk_level"] == "critical":
        preview["status"] = "blocked"
        preview["reason"] = "Risk level is critical — use force override"
        return preview

    exec_result = await ssh.execute(execute_cmd)
    if not exec_result.success:
        preview["status"] = "failed"
        preview["error"] = exec_result.stderr.strip()
        return preview

    verify = await ssh.execute(f"getsebool {quote_arg(name)}")
    verify_val = ""
    if "-->" in verify.stdout:
        verify_val = verify.stdout.split("-->")[1].strip()

    preview["status"] = "applied"
    preview["verified_value"] = verify_val
    return preview


async def generate_module(
    ssh: SSHBackend,
    name: str,
    from_denials: str = "1h",
    source_type: str | None = None,
) -> dict:
    """Generate a targeted CIL module from observed denials."""
    try:
        name = sanitize_identifier(name, "name")
        if source_type:
            source_type = sanitize_selinux_type(source_type, "source_type")
    except SanitizationError as e:
        return e.to_dict()

    check = await _check_enforcing(ssh)
    if isinstance(check, dict):
        return check

    ts = parse_time_spec(from_denials)
    cmd = f"ausearch -m AVC -ts {ts} 2>/dev/null"
    if source_type:
        cmd += f" | grep 'scontext=.*:{quote_arg(source_type)}:'"

    result = await ssh.execute(cmd)
    denials = parse_avc_denials(result.stdout)

    if not denials:
        return {
            "action": "generate_module",
            "name": name,
            "status": "no_denials",
            "message": f"No AVC denials found in last {from_denials}",
        }

    rules = []
    seen = set()
    for d in denials:
        if "source_type" not in d:
            continue
        perms = d.get("permissions", [])
        if isinstance(perms, str):
            perms = [perms]
        key = (d["source_type"], d["target_type"], d["tclass"], tuple(perms))
        if key in seen:
            continue
        seen.add(key)
        rules.append(
            {
                "source": d["source_type"],
                "target": d["target_type"],
                "tclass": d["tclass"],
                "permissions": perms,
            }
        )

    cil_lines = [f"(block {name}"]
    for r in rules:
        perm_str = " ".join(r["permissions"])
        cil_lines.append(f"  (allow {r['source']} {r['target']} ({r['tclass']} ({perm_str})))")
    cil_lines.append(")")
    cil_content = "\n".join(cil_lines)

    risk = score_module_change(name=name, cil_rules=rules)

    bool_alternatives = []
    for r in rules:
        bool_cmd = (
            f"sesearch --allow -s {quote_arg(r['source'])} -t {quote_arg(r['target'])} "
            f"-c {quote_arg(r['tclass'])} -b 2>/dev/null"
        )
        bool_result = await ssh.execute(bool_cmd)
        bool_rules = parse_sesearch_allow(bool_result.stdout)
        for br in bool_rules:
            if br.get("conditional"):
                bool_alternatives.append(
                    {
                        "boolean": br["conditional"],
                        "would_fix": f"{r['source']} -> {r['target']}:{r['tclass']}",
                    }
                )

    return {
        "action": "generate_module",
        "name": name,
        "status": "generated",
        "cil_content": cil_content,
        "rules_count": len(rules),
        "from_denials_count": len(denials),
        "risk_assessment": risk,
        "boolean_alternatives": bool_alternatives,
        "next_step": f"Use manage.load_module with name='{name}' to apply",
    }


async def load_module(
    ssh: SSHBackend,
    name: str,
    cil: str,
    dry_run: bool = True,
) -> dict:
    """Load a CIL policy module."""
    try:
        name = sanitize_identifier(name, "name")
        cil = sanitize_cil(cil, "cil")
    except SanitizationError as e:
        return e.to_dict()

    check = await _check_enforcing(ssh)
    if isinstance(check, dict):
        return check

    cil_rules = []
    for line in cil.split("\n"):
        line = line.strip()
        if line.startswith("(allow "):
            parts = line.strip("()").split()
            if len(parts) >= 3:
                cil_rules.append(
                    {
                        "source": parts[1],
                        "target": parts[2],
                        "permissions": [],
                    }
                )

    risk = score_module_change(name=name, cil_rules=cil_rules)

    preview = {
        "action": "load_module",
        "name": name,
        "rules_count": len(cil_rules),
        "risk_assessment": risk,
    }

    if dry_run:
        preview["status"] = "preview"
        preview["command"] = f"semodule -i <tmpdir>/{name}.cil"
        return preview

    if risk["risk_level"] == "critical":
        preview["status"] = "blocked"
        preview["reason"] = "Risk level is critical"
        return preview

    tmpdir_result = await ssh.execute("mktemp -d /tmp/emcp.XXXXXXXX")
    if not tmpdir_result.success:
        preview["status"] = "failed"
        preview["error"] = "Failed to create temp directory"
        return preview
    tmpdir = tmpdir_result.stdout.strip()

    cil_path = f"{tmpdir}/{name}.cil"
    write_result = await ssh.execute(f"cat > {quote_arg(cil_path)} << 'EMCP_EOF'\n{cil}\nEMCP_EOF")
    if not write_result.success:
        await ssh.execute(f"rm -rf {quote_arg(tmpdir)}")
        preview["status"] = "failed"
        preview["error"] = "Failed to write CIL file"
        return preview

    install_result = await ssh.execute(f"semodule -i {quote_arg(cil_path)}")
    if not install_result.success:
        await ssh.execute(f"rm -rf {quote_arg(tmpdir)}")
        preview["status"] = "failed"
        preview["error"] = install_result.stderr.strip()
        return preview

    verify = await ssh.execute(f"semodule -l | grep '^{name}'")
    preview["status"] = "applied"
    preview["verified_loaded"] = bool(verify.stdout.strip())

    await ssh.execute(f"rm -rf {quote_arg(tmpdir)}")
    return preview


async def remove_module(
    ssh: SSHBackend,
    name: str,
    dry_run: bool = True,
) -> dict:
    """Remove a loaded policy module."""
    try:
        name = sanitize_identifier(name, "name")
    except SanitizationError as e:
        return e.to_dict()

    check = await _check_enforcing(ssh)
    if isinstance(check, dict):
        return check

    loaded = await ssh.execute(f"semodule -l | grep '^{name}'")
    if not loaded.stdout.strip():
        return {
            "action": "remove_module",
            "name": name,
            "status": "not_found",
            "message": f"Module '{name}' is not currently loaded",
        }

    preview = {
        "action": "remove_module",
        "name": name,
        "command": f"semodule -r {quote_arg(name)}",
    }

    if dry_run:
        preview["status"] = "preview"
        preview["warning"] = (
            "Removing this module may cause denials to resume for the access it was allowing"
        )
        return preview

    result = await ssh.execute(f"semodule -r {quote_arg(name)}")
    if not result.success:
        preview["status"] = "failed"
        preview["error"] = result.stderr.strip()
        return preview

    verify = await ssh.execute(f"semodule -l | grep '^{name}'")
    preview["status"] = "removed"
    preview["verified_removed"] = not bool(verify.stdout.strip())
    return preview


async def set_file_context(
    ssh: SSHBackend,
    path: str,
    context_type: str,
    dry_run: bool = True,
) -> dict:
    """Add a persistent file context rule and relabel."""
    try:
        path = sanitize_context_path(path, "path")
        context_type = sanitize_selinux_type(context_type, "context_type")
    except SanitizationError as e:
        return e.to_dict()

    check = await _check_enforcing(ssh)
    if isinstance(check, dict):
        return check

    fcontext_cmd = f"semanage fcontext -a -t {quote_arg(context_type)} {quote_arg(path)}"
    restorecon_path = path.split("(")[0]
    restorecon_cmd = f"restorecon -Rv {quote_arg(restorecon_path)}"

    preview = {
        "action": "set_file_context",
        "path": path,
        "target_type": context_type,
        "commands": [fcontext_cmd, restorecon_cmd],
    }

    if dry_run:
        preview["status"] = "preview"
        return preview

    fc_result = await ssh.execute(fcontext_cmd)
    if not fc_result.success:
        if "already defined" in fc_result.stderr:
            mod_cmd = f"semanage fcontext -m -t {quote_arg(context_type)} {quote_arg(path)}"
            fc_result = await ssh.execute(mod_cmd)

        if not fc_result.success:
            preview["status"] = "failed"
            preview["error"] = fc_result.stderr.strip()
            return preview

    rc_result = await ssh.execute(restorecon_cmd)
    preview["status"] = "applied"
    preview["restorecon_output"] = rc_result.stdout.strip()
    return preview
