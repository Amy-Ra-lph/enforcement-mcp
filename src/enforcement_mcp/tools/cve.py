"""CVE exposure and containment tracking tools."""

import json
import re

from enforcement_mcp.cve_api import fetch_cve, parse_cve_response
from enforcement_mcp.exploit_map import build_exploit_chain, map_cve_to_techniques
from enforcement_mcp.parsers import parse_getenforce, parse_sesearch_allow
from enforcement_mcp.sanitize import quote_arg
from enforcement_mcp.ssh import SSHBackend

CONTAINMENT_STATE_PATH = "/var/lib/enforcement-mcp/containments.json"


async def cve_exposure(ssh: SSHBackend, cve_id: str) -> dict:
    """Assess current policy effectiveness against a CVE exploit chain."""
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return {"error": "invalid_cve_id", "message": f"Invalid CVE ID format: {cve_id}"}

    mode = parse_getenforce((await ssh.execute("getenforce")).stdout)
    if mode == "disabled":
        return {
            "error": "selinux_disabled",
            "message": "SELinux is disabled — no policy-based containment possible",
        }

    raw = await fetch_cve(cve_id)
    if "error" in raw:
        return {"error": "cve_fetch_failed", "detail": raw}

    cve = parse_cve_response(raw)
    if not cve:
        return {"error": "cve_parse_failed", "cve_id": cve_id}

    source_type = _infer_source_type(cve.affected_packages)
    techniques = map_cve_to_techniques(cve.cwe, cve.affected_packages)
    chain = build_exploit_chain(source_type, techniques)

    blocked_count = 0
    for step in chain:
        step_blocked = True
        blocking_rule = None
        for perm in step["required_permissions"]:
            cmd = (
                f"sesearch --allow -s {quote_arg(perm['source'])} -t {quote_arg(perm['target'])} "
                f"-c {quote_arg(perm['class'])} -p {quote_arg(perm['perm'])} 2>/dev/null"
            )
            result = await ssh.execute(cmd)
            rules = parse_sesearch_allow(result.stdout)
            if rules:
                step_blocked = False
                break
            else:
                blocking_rule = (
                    f"No allow: {perm['source']} -> {perm['target']}:{perm['class']}:{perm['perm']}"
                )

        step["blocked"] = step_blocked
        step["blocking_rule"] = blocking_rule if step_blocked else None
        if step_blocked:
            blocked_count += 1

    total = len(chain)
    containment_score = int(blocked_count / total * 100) if total > 0 else 0

    if containment_score >= 80:
        residual = "low — most exploit steps blocked by current policy"
    elif containment_score >= 50:
        residual = "medium — some exploit steps blocked, but gaps remain"
    elif containment_score > 0:
        residual = "high — few exploit steps blocked, significant exposure"
    else:
        residual = "critical — no exploit steps blocked by current policy"

    return {
        "cve": cve.model_dump(),
        "source_type": source_type,
        "exploit_chain": chain,
        "containment_score": containment_score,
        "residual_risk": residual,
        "total_steps": total,
        "blocked_steps": blocked_count,
        "selinux_mode": mode,
    }


async def active_containments(ssh: SSHBackend) -> dict:
    """List temporary CVE containment modules currently in effect."""
    result = await ssh.execute(f"cat {CONTAINMENT_STATE_PATH} 2>/dev/null")
    if not result.success or not result.stdout.strip():
        return {"containments": [], "total": 0}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"containments": [], "total": 0, "error": "corrupt_state_file"}

    containments = data if isinstance(data, list) else data.get("containments", [])

    for c in containments:
        cve_id = c.get("cve_id", "")
        module_name = c.get("module_name", "")
        loaded = await ssh.execute(f"semodule -l 2>/dev/null | grep -F {quote_arg(module_name)}")
        c["module_loaded"] = bool(loaded.stdout.strip())

        if cve_id and c.get("fixed_in"):
            for pkg in c["fixed_in"][:3]:
                pkg_name = pkg.split("-")[0] if "-" in pkg else pkg
                rpm_check = await ssh.execute(f"rpm -q {quote_arg(pkg_name)} 2>/dev/null")
                if rpm_check.success:
                    c["patched_rpm_available"] = True
                    c["safe_to_remove"] = True
                    break

    return {"containments": containments, "total": len(containments)}


def _infer_source_type(packages: list[str]) -> str:
    """Infer likely SELinux source type from package names."""
    pkg_map = {
        "httpd": "httpd_t",
        "nginx": "httpd_t",
        "mod_ssl": "httpd_t",
        "openssh": "sshd_t",
        "openssh-server": "sshd_t",
        "sshd": "sshd_t",
        "postfix": "postfix_master_t",
        "sendmail": "sendmail_t",
        "named": "named_t",
        "bind": "named_t",
        "mysqld": "mysqld_t",
        "mariadb": "mysqld_t",
        "postgresql": "postgresql_t",
        "cups": "cupsd_t",
        "samba": "smbd_t",
        "smb": "smbd_t",
        "krb5": "krb5kdc_t",
        "krb5-server": "krb5kdc_t",
        "sssd": "sssd_t",
        "systemd": "init_t",
        "polkit": "policykit_t",
        "sudo": "sudo_t",
        "dbus": "system_dbusd_t",
        "NetworkManager": "NetworkManager_t",
        "firewalld": "firewalld_t",
        "chronyd": "chronyd_t",
        "rsyslog": "syslogd_t",
        "tomcat": "tomcat_t",
        "java": "java_t",
        "python": "unconfined_t",
        "kernel": "kernel_t",
    }

    for pkg in packages:
        name = pkg.split("-")[0] if "-" in pkg else pkg
        if name in pkg_map:
            return pkg_map[name]

    return "unconfined_t"
