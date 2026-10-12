# linux-mcp Integration Guide

How to consume enforcement-mcp's SELinux diagnosis and remediation playbook
generation from [linux-mcp](https://github.com/bsmithgit/linux-mcp-server) or
any other MCP server.

## Architecture

enforcement-mcp organizes tools into three tiers:

| Tier | Scope | Auth | SSH | Safe for upstream |
|------|-------|------|-----|-------------------|
| **1 — Diagnosis** | Read-only system queries | No | Yes | Yes |
| **2 — Remediation** | Generate fix playbooks (YAML text output) | No | Optional | Yes |
| **3 — Management** | Mutating policy changes | Yes (strict mode) | Yes | No |

linux-mcp should consume **Tier 1 + Tier 2 only**. Tier 3 stays in
enforcement-mcp where identity verification, RBAC, audit trail, and risk
gating are enforced.

## What linux-mcp Gets

### Tier 1: Diagnosis Tools (read-only)

From `enforcement_mcp.modules.selinux`:

| Tool | Description |
|------|-------------|
| `selinux_status` | SELinux mode, policy type, loaded modules |
| `selinux_booleans` | Boolean list with current state |
| `selinux_file_context` | Expected vs actual file context |
| `selinux_denials` | Recent AVC denials, parsed and structured |
| `selinux_policy_query` | Query allow rules for a source type |
| `selinux_denial_explain` | Explain why a denial happened |

### Tier 2: Remediation Playbook Generation (read-only output)

From `enforcement_mcp.tools.remediate`:

| Finding Type | Strategies (ranked by risk) | SSH Required |
|-------------|---------------------------|--------------|
| `denial` | Relabel → boolean toggle → custom CIL module | Yes (sesearch lookup) |
| `file_context` | restorecon → permanent fcontext rule | No |
| `fapolicyd_block` | Add to trust DB | No |
| `aide_change` | Investigate → accept baseline update | No |

Each alternative includes:
- Ansible playbook YAML using `fedora.linux_system_roles`
- Risk assessment (0–100 score, level, recommendation)
- Rollback instructions
- Blast radius analysis

## Integration: Package Dependency

### Step 1: Add dependency

```toml
# linux-mcp pyproject.toml
[project]
dependencies = [
    "enforcement-mcp",
    # ... existing deps
]
```

Or for minimal footprint (parsers only, zero deps beyond pydantic):

```toml
dependencies = [
    "enforcement-mcp-parsers",
]
```

### Step 2: Register Tier 1 tools

```python
# linux-mcp server.py
from enforcement_mcp.modules.selinux import register_readonly_tools

# Assuming linux-mcp has an ssh_provider function
async def get_ssh():
    return ssh_backend  # your existing SSH connection

register_readonly_tools(mcp, get_ssh)
```

This registers 6 read-only SELinux tools under the `diagnosis.*` namespace.
No root required. No policy modifications.

### Step 3: Register Tier 2 playbook generation

```python
from enforcement_mcp.tools.remediate import generate_playbook

@mcp.tool(name="diagnosis.generate_playbook")
async def tool_generate_playbook(
    finding_type: str,
    source_type: str | None = None,
    target_type: str | None = None,
    tclass: str | None = None,
    permission: str | None = None,
    path: str | None = None,
    expected_type: str | None = None,
    actual_type: str | None = None,
    changed_paths: list[str] | None = None,
    action: str | None = None,
) -> dict:
    """Generate Ansible remediation playbook with risk assessment."""
    ssh = await get_ssh()  # None is OK for non-denial types
    params = {k: v for k, v in {
        "source_type": source_type, "target_type": target_type,
        "tclass": tclass, "permission": permission, "path": path,
        "expected_type": expected_type, "actual_type": actual_type,
        "changed_paths": changed_paths, "action": action,
    }.items() if v is not None}
    return await generate_playbook(ssh, finding_type=finding_type, **params)
```

### Step 4: Without SSH (offline mode)

Three of four finding types work without SSH:

```python
from enforcement_mcp.tools.remediate import generate_playbook

# No SSH needed — returns playbook YAML directly
result = await generate_playbook(
    None,  # no SSH backend
    finding_type="file_context",
    path="/var/www/html/app.log",
    expected_type="httpd_sys_content_t",
    actual_type="var_log_t",
)
print(result["recommended"]["playbook"])
```

Only `denial` type uses SSH (to run `sesearch -b` for boolean lookup). If SSH
is `None`, the boolean alternative is skipped and only relabel + custom module
options are generated.

## Security Considerations

### Input validation is built-in

`generate_playbook` validates all inputs through `sanitize.py` before
processing:

- `source_type`, `target_type`, `expected_type`, `actual_type` → `sanitize_selinux_type()`
- `tclass` → `sanitize_selinux_class()`
- `permission` → `sanitize_selinux_permission()`
- `path`, `changed_paths` → `sanitize_path()`
- Shell arguments in sesearch → `quote_arg()` (shlex.quote)

Invalid input returns `{"error": "invalid_input", "detail": "..."}` — no
command execution occurs.

### Playbook output is text only

`generate_playbook` returns YAML strings. It never:
- Executes `ansible-playbook`
- Writes files to disk
- Modifies SELinux policy
- Connects to Ansible Tower/AAP

The human operator (or their automation) decides whether to apply the playbook.

### Risk assessment is included

Every alternative carries a risk assessment from enforcement-mcp's scoring
engine. Consumers get safety information for free:

```json
{
  "risk_score": 18,
  "risk_level": "low",
  "recommendation": "proceed",
  "blast_radius": {"rules_unlocked": 3, "domains_affected": ["httpd_t"]},
  "reversibility": {"method": "setsebool -P httpd_enable_homedirs off"}
}
```

### Jinja2 in YAML output

`yaml.dump()` does not escape Ansible Jinja2 syntax (`{{ }}`). Paths
containing `{{ }}` pass through to the playbook output. This is by design —
the `sanitize_path()` validator rejects shell metacharacters, but `{{ }}` is
valid in Ansible variable references like `{{ target_hosts }}`. The playbook
header includes a review warning.

## Workflow: Diagnosis → Remediation

The intended agent workflow chains diagnosis into remediation:

```
1. Agent calls diagnosis.troubleshoot
   → Returns: {root_cause: "selinux", denials_found: [{source_type: "httpd_t", ...}]}

2. Agent calls diagnosis.generate_playbook with the denial details
   → Returns: ranked alternatives with playbooks + risk scores

3. Agent presents the recommended fix to the human operator
   → Includes: risk score, blast radius, rollback instructions

4. Human reviews and runs: ansible-playbook fix.yml -e target_hosts=webserver01
```

Steps 1–3 are fully automated and read-only. Step 4 requires human approval.

## What linux-mcp Does NOT Get

| Capability | Why excluded |
|-----------|--------------|
| `manage.set_boolean` | Mutates policy — needs identity + RBAC |
| `manage.load_module` | Loads CIL into kernel policy |
| `manage.cve_contain` | Generates + loads containment modules |
| `manage.fapolicyd_trust_add` | Modifies fapolicyd trust DB |
| Risk gating (critical block) | Only relevant for management tools |
| Audit trail | Only relevant for management tools |
| Identity verification | Only relevant for management tools |

If linux-mcp wants management capabilities, it should delegate to
enforcement-mcp via MCP-to-MCP composition rather than importing Tier 3 tools
directly.

## Versioning

enforcement-mcp follows semver. The module API is:

| Surface | Stability |
|---------|-----------|
| `register_readonly_tools()` | Stable — matches upstream contribution |
| `generate_playbook()` | Stable — input/output contract frozen |
| `score_*` risk functions | Stable — scoring factors may evolve |
| Internal parsers/models | May change between minor versions |

Pin to `>=0.5.0,<1.0.0` in your dependency spec.

## Testing

enforcement-mcp ships 411 tests including:
- 25 tests for `generate_playbook` (all finding types, risk integration, YAML validity)
- 6 injection-specific tests (shell injection rejected for all input params)
- 27 parser hardening tests (size limits, path sanitization)
- 17 Hypothesis fuzz tests (200 examples per parser)

Run the remediation tests standalone:

```bash
pip install enforcement-mcp[dev]
pytest tests/test_tools/test_remediate.py -v
```
