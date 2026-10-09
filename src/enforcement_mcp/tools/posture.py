"""Composite diagnosis tools — host posture and troubleshoot."""

from enforcement_mcp.parsers import (
    parse_avc_denials,
    parse_fanotify_denials,
    parse_getenforce,
    parse_getsebool,
    parse_semanage_login,
)
from enforcement_mcp.sanitize import (
    SanitizationError,
    quote_arg,
    sanitize_path,
    sanitize_process_name,
)
from enforcement_mcp.ssh import SSHBackend


async def host_posture(ssh: SSHBackend) -> dict:
    """Comprehensive security posture summary."""
    mode = parse_getenforce((await ssh.execute("getenforce")).stdout)

    policy_type = "unknown"
    config_result = await ssh.execute("grep '^SELINUXTYPE=' /etc/selinux/config 2>/dev/null")
    if config_result.success and "=" in config_result.stdout:
        policy_type = config_result.stdout.strip().split("=")[1]

    avc_result = await ssh.execute("ausearch -m AVC -ts today 2>/dev/null")
    avc_denials = parse_avc_denials(avc_result.stdout)
    denial_count = len(avc_denials)

    type_counts: dict[str, int] = {}
    for d in avc_denials:
        st = d.get("source_type", "unknown")
        type_counts[st] = type_counts.get(st, 0) + 1
    top_types = sorted(type_counts, key=lambda k: type_counts[k], reverse=True)[:5]

    modules_result = await ssh.execute("semodule -l 2>/dev/null | grep -v '^[a-z].*\t$'")
    custom_modules: list[str] = []
    if modules_result.success:
        for line in modules_result.stdout.strip().split("\n"):
            if line.strip():
                custom_modules.append(line.strip().split()[0])

    bools_result = await ssh.execute("getsebool -a")
    all_bools = parse_getsebool(bools_result.stdout)
    non_default = [b["name"] + "=" + b["state"] for b in all_bools if b["state"] == "on"]

    selinux_info = {
        "mode": mode,
        "policy_type": policy_type,
        "denial_count_24h": denial_count,
        "top_denied_types": top_types,
        "custom_modules": custom_modules[:10],
        "booleans_non_default": non_default[:20],
    }

    fap_installed = (await ssh.execute("rpm -q fapolicyd 2>/dev/null")).exit_code == 0
    fapolicyd_info: dict
    if fap_installed:
        fap_active = (
            await ssh.execute("systemctl is-active fapolicyd 2>/dev/null")
        ).stdout.strip() == "active"
        fap_rules_result = await ssh.execute(
            "cat /etc/fapolicyd/rules.d/*.rules 2>/dev/null | grep -c -v '^#\\|^$'"
        )
        fap_rules = int(fap_rules_result.stdout.strip()) if fap_rules_result.success else 0
        fap_trust_result = await ssh.execute("fapolicyd-cli --list 2>/dev/null | wc -l")
        fap_trust = int(fap_trust_result.stdout.strip()) if fap_trust_result.success else 0
        fap_denials_result = await ssh.execute("ausearch -m FANOTIFY -ts today 2>/dev/null")
        fap_denial_list = parse_fanotify_denials(fap_denials_result.stdout)

        fapolicyd_info = {
            "installed": True,
            "active": fap_active,
            "rules": fap_rules,
            "trust_db_entries": fap_trust,
            "denials_24h": len(fap_denial_list),
        }
    else:
        fapolicyd_info = {"installed": False, "active": False}

    login_result = await ssh.execute("semanage login -l 2>/dev/null")
    mls_mappings = parse_semanage_login(login_result.stdout)
    mls_info = {
        "policy": policy_type,
        "user_mappings": len(mls_mappings),
    }

    score = 100
    findings = []

    if mode != "enforcing":
        score -= 30
        findings.append(f"-30: SELinux mode is {mode}, not enforcing")
    if denial_count > 0:
        penalty = min(denial_count, 20)
        score -= penalty
        findings.append(f"-{penalty}: {denial_count} AVC denials in last 24h")
    if not fap_installed:
        score -= 15
        findings.append("-15: fapolicyd not installed")
    elif not fapolicyd_info.get("active"):
        score -= 10
        findings.append("-10: fapolicyd installed but not active")
    if len(non_default) > 5:
        score -= 5
        findings.append(f"-5: {len(non_default)} non-default SELinux booleans enabled")

    score = max(0, score)

    return {
        "selinux": selinux_info,
        "fapolicyd": fapolicyd_info,
        "mls": mls_info,
        "posture_score": score,
        "findings": findings,
    }


async def troubleshoot(
    ssh: SSHBackend,
    symptom: str,
    process: str | None = None,
    path: str | None = None,
) -> dict:
    """Composite diagnostic — find root cause of a blocked operation."""
    chain = []
    denials_found: list[dict] = []
    not_the_cause = []

    mode = parse_getenforce((await ssh.execute("getenforce")).stdout)
    chain.append({"step": "SELinux mode", "finding": mode})

    if mode != "disabled" and process:
        try:
            process = sanitize_process_name(process)
        except SanitizationError as e:
            return e.to_dict()
        avc_result = await ssh.execute(
            f"ausearch -m AVC -ts recent 2>/dev/null | grep {quote_arg(process)}"
        )
        avc_denials = parse_avc_denials(avc_result.stdout)
        if avc_denials:
            chain.append(
                {
                    "step": f"AVC denials for {process}",
                    "finding": f"{len(avc_denials)} denial(s) found",
                }
            )
            denials_found.extend(avc_denials)
        else:
            chain.append({"step": f"AVC denials for {process}", "finding": "none"})
            not_the_cause.append(
                {
                    "subsystem": "selinux",
                    "reason": f"No AVC denials for {process}",
                }
            )
    elif mode == "disabled":
        not_the_cause.append({"subsystem": "selinux", "reason": "SELinux is disabled"})

    fap_installed = (await ssh.execute("rpm -q fapolicyd 2>/dev/null")).exit_code == 0
    if fap_installed:
        fap_result = await ssh.execute("ausearch -m FANOTIFY -ts recent 2>/dev/null")
        fap_denials = parse_fanotify_denials(fap_result.stdout)
        if path:
            fap_denials = [d for d in fap_denials if path in str(d.get("exe", ""))]
        if fap_denials:
            chain.append(
                {
                    "step": "fapolicyd denials",
                    "finding": f"{len(fap_denials)} denial(s) found",
                }
            )
            denials_found.extend(fap_denials)
        else:
            chain.append({"step": "fapolicyd denials", "finding": "none"})
            not_the_cause.append(
                {
                    "subsystem": "fapolicyd",
                    "reason": "No FANOTIFY denials",
                }
            )
    else:
        not_the_cause.append(
            {
                "subsystem": "fapolicyd",
                "reason": "fapolicyd not installed",
            }
        )

    if path:
        try:
            path = sanitize_path(path)
        except SanitizationError as e:
            return e.to_dict()
        dac_result = await ssh.execute(f"ls -la {quote_arg(path)} 2>/dev/null")
        if dac_result.success:
            chain.append({"step": "DAC permissions", "finding": dac_result.stdout.strip()})
        else:
            chain.append(
                {
                    "step": "DAC permissions",
                    "finding": "path not found or not accessible",
                }
            )

    root_cause = "unknown"
    confidence = "low"

    selinux_denials = [d for d in denials_found if "source_type" in d]
    fapolicyd_denials_found = [d for d in denials_found if "obj_trust" in d]

    if selinux_denials:
        root_cause = "selinux"
        confidence = "high"
    elif fapolicyd_denials_found:
        root_cause = "fapolicyd"
        confidence = "high"
    elif not denials_found:
        root_cause = "not_enforcement"
        confidence = "high"

    result: dict = {
        "symptom": symptom,
        "root_cause": root_cause,
        "confidence": confidence,
        "chain": chain,
        "denials_found": denials_found,
        "not_the_cause": not_the_cause,
    }

    if root_cause == "not_enforcement":
        result["suggestions"] = [
            "Check application configuration",
            "Check application error logs",
            "Verify the target file/service exists and is accessible",
        ]

    return result
