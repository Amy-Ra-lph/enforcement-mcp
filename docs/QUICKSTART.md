# Getting Started with enforcement-mcp

Get from zero to diagnosing SELinux denials in under 5 minutes.

## Prerequisites

- A RHEL 9 or 10 host with SSH access (key-based auth)
- Python 3.12+ on your local machine (or use the container)
- `setools-console` installed on the target host (`dnf install -y setools-console`)

## 1. Install and configure

```bash
# Install from GitHub
pip install git+https://github.com/Amy-Ra-lph/enforcement-mcp.git

# Auto-configure your MCP client (Claude Code, Claude Desktop, Cursor)
enforcement-mcp setup webserver01.example.com

# Verify the target host has required packages
enforcement-mcp check webserver01.example.com
```

The `setup` command detects installed MCP clients and writes the config
snippet for you. The `check` command SSHes to the target and reports
which prerequisites are installed (setools-console, audit, fapolicyd, etc.).

Or start the server with a default target (no env var needed):

```bash
enforcement-mcp serve webserver01.example.com
enforcement-mcp serve --transport sse webserver01.example.com
```

Or use environment variables:

```bash
export ENFORCEMENT_MCP_TARGET=myhost.example.com
export ENFORCEMENT_MCP_USER=root           # default
export ENFORCEMENT_MCP_KEY_FILE=~/.ssh/id_ed25519  # optional
```

## 2. First diagnosis: "Why is httpd blocked?"

Connect your MCP client (Claude Desktop, Claude Code, or any MCP-compatible agent) and call:

```json
{
  "tool": "diagnosis.troubleshoot",
  "arguments": {
    "symptom": "httpd cannot serve files from /home/jsmith/public_html",
    "process": "httpd",
    "path": "/home/jsmith/public_html"
  }
}
```

You get back structured JSON:

```json
{
  "root_cause": "selinux",
  "confidence": "high",
  "denials_found": [
    {
      "source_type": "httpd_t",
      "target_type": "user_home_t",
      "tclass": "file",
      "permission": "read"
    }
  ],
  "not_the_cause": [
    {"subsystem": "fapolicyd", "reason": "No FANOTIFY denials"}
  ]
}
```

No more parsing raw `ausearch` output.

## 3. Understand why: explain the denial

```json
{
  "tool": "diagnosis.denial_explain",
  "arguments": {
    "source": "httpd_t",
    "target": "user_home_t",
    "tclass": "file",
    "permission": "read"
  }
}
```

Response:

```json
{
  "cause": "boolean",
  "boolean": "httpd_enable_homedirs",
  "current_state": "off",
  "fix": "setsebool -P httpd_enable_homedirs on",
  "explanation": "Access from httpd_t to user_home_t:file:read is gated by boolean 'httpd_enable_homedirs' (currently off)"
}
```

## 4. Assess risk before fixing

Before toggling that boolean, check the risk:

```json
{
  "tool": "manage.assess_risk",
  "arguments": {
    "change_type": "boolean",
    "name": "httpd_enable_homedirs",
    "value": true
  }
}
```

Response:

```json
{
  "risk_score": 18,
  "risk_level": "low",
  "blast_radius": {
    "rules_unlocked": 3,
    "domains_affected": ["httpd_t"]
  },
  "reversibility": {
    "method": "setsebool -P httpd_enable_homedirs off",
    "difficulty": "easy"
  },
  "recommendation": "proceed"
}
```

Score 18/100, low risk. Safe to proceed.

## 5. Generate a remediation playbook

Instead of running commands manually, generate an Ansible playbook that uses
[linux-system-roles](https://github.com/linux-system-roles):

```json
{
  "tool": "diagnosis.generate_playbook",
  "arguments": {
    "finding_type": "denial",
    "source_type": "httpd_t",
    "target_type": "user_home_t",
    "tclass": "file",
    "permission": "read",
    "path": "/home/jsmith/public_html"
  }
}
```

Response:

```json
{
  "finding_type": "denial",
  "recommended": {
    "strategy": "relabel",
    "scope": "narrowest — fixes one file, no policy change",
    "risk": {"risk_score": 0, "risk_level": "low", "recommendation": "proceed"},
    "playbook": "# Remediation: Relabel /home/jsmith/public_html...\n---\n..."
  },
  "alternatives": [
    {"strategy": "relabel", "risk": {"risk_score": 0}},
    {"strategy": "boolean", "boolean": "httpd_read_user_content", "risk": {"risk_score": 18}},
    {"strategy": "custom_module", "risk": {"risk_score": 5}}
  ],
  "total_options": 3
}
```

Alternatives ranked safest-first. Each includes a ready-to-run playbook using
`fedora.linux_system_roles.selinux`. Review the recommended option, then apply
it with `ansible-playbook` — or proceed to direct management tools below.

The tool supports four finding types:

| Finding Type | When to use |
|-------------|-------------|
| `denial` | SELinux AVC denial (from `troubleshoot` or `avc_denials`) |
| `file_context` | SELinux context mismatch (from `file_context`) |
| `fapolicyd_block` | fapolicyd blocking a binary (from `fapolicyd_denials`) |
| `aide_change` | AIDE detected unexpected file changes |

## 6. Apply the fix (direct)

```json
{
  "tool": "manage.set_boolean",
  "arguments": {
    "name": "httpd_enable_homedirs",
    "value": true,
    "persistent": true,
    "dry_run": false
  }
}
```

Response:

```json
{
  "status": "applied",
  "verified_value": "on",
  "risk_assessment": {"risk_score": 18, "risk_level": "low"}
}
```

## 7. Check your security posture

```json
{
  "tool": "diagnosis.host_posture",
  "arguments": {}
}
```

Returns a 0-100 posture score with findings:

```json
{
  "posture_score": 85,
  "selinux": {"mode": "enforcing", "denial_count_24h": 3},
  "fapolicyd": {"installed": true, "active": true},
  "findings": ["-15: 3 AVC denials in last 24h"]
}
```

## 8. CVE containment (when a patch isn't ready yet)

Check if your policy blocks a CVE's exploit chain:

```json
{
  "tool": "diagnosis.cve_exposure",
  "arguments": {"cve": "CVE-2024-6387"}
}
```

If gaps exist, generate containment:

```json
{
  "tool": "manage.cve_contain",
  "arguments": {"cve": "CVE-2024-6387", "strategy": "all"}
}
```

Returns multiple containment options (minimal, network isolation, full lockdown) with CIL modules and risk assessments. Apply the one that fits, then remove it after patching with `manage.containment_expire`.

## Common workflows

| Scenario | Tools to use |
|----------|-------------|
| "Why is my app blocked?" | `troubleshoot` → `denial_explain` → `generate_playbook` or `set_boolean` |
| "Is this host hardened?" | `host_posture` |
| "What does this boolean do?" | `assess_risk` with `change_type=boolean` |
| "New binary won't run" | `fapolicyd_trust_check` → `generate_playbook(fapolicyd_block)` or `fapolicyd_trust_add` |
| "CVE dropped, no patch yet" | `cve_exposure` → `cve_contain` → `containment_expire` (after patch) |
| "Need a custom policy module" | `generate_module` → review CIL → `load_module` |
| "Give me an Ansible playbook" | `generate_playbook` → review YAML → `ansible-playbook` |
| "AIDE flagged changes" | `generate_playbook(aide_change)` → investigate → accept with playbook |

## MCP client configuration

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "enforcement-mcp": {
      "command": "enforcement-mcp",
      "args": ["serve", "myhost.example.com"]
    }
  }
}
```

### Claude Code

Add to your MCP settings or `.mcp.json`:

```json
{
  "enforcement-mcp": {
    "command": "enforcement-mcp",
    "args": ["serve", "myhost.example.com"]
  }
}
```

The default target can also be set via env var instead of args:

```json
{
  "enforcement-mcp": {
    "command": "enforcement-mcp",
    "args": [],
    "env": {
      "ENFORCEMENT_MCP_TARGET": "myhost.example.com"
    }
  }
}
```

## Identity & RBAC (optional)

Pass an OAuth JWT or SPIFFE ID to management tools for access control:

```json
{
  "tool": "manage.set_boolean",
  "arguments": {
    "name": "httpd_enable_homedirs",
    "value": true,
    "dry_run": false,
    "identity_token": "eyJhbGciOiJSUzI1NiIs..."
  }
}
```

Configure identity enforcement:

```bash
export ENFORCEMENT_MCP_IDENTITY_MODE=oauth        # or spiffe, both
export ENFORCEMENT_MCP_AUTHZ_POLICY=strict         # or permissive (log only)
export ENFORCEMENT_MCP_OAUTH_ISSUER=https://keycloak.example.com/realms/infra
export ENFORCEMENT_MCP_OAUTH_AUDIENCE=enforcement-mcp
export ENFORCEMENT_MCP_OAUTH_JWKS_URI=https://keycloak.example.com/realms/infra/protocol/openid-connect/certs
```

For SPIFFE workloads, pass the SPIFFE ID directly:

```json
{
  "identity_token": "spiffe://example.com/operator/sre-agent"
}
```

Roles (`admin`, `operator`, `viewer`, `containment`) control which tools
each caller can access. All invocations are logged to an audit trail on the
remote host.

## Sysadmin workflow: laptop + Claude/Cursor

enforcement-mcp runs **on your laptop** and SSH-proxies to whatever RHEL
host you're managing. Nothing gets installed on the target server — your
existing SSH key is all you need.

### One-time setup

```bash
# Install (pick one)
pip install git+https://github.com/Amy-Ra-lph/enforcement-mcp.git
podman pull quay.io/rhel-security/enforcement-mcp # container

# Auto-configure your MCP client and verify the target
enforcement-mcp setup webserver01.example.com
enforcement-mcp check webserver01.example.com
```

The `setup` command detects Claude Code, Claude Desktop, and Cursor, then
writes the config for you. The `check` command SSHes to the target and
reports PASS/MISS for each prerequisite.

Or configure manually:

**Claude Code** (`~/.claude/settings.json` or project `.mcp.json`):

```json
{
  "enforcement-mcp": {
    "command": "enforcement-mcp",
    "args": ["serve", "webserver01.example.com"]
  }
}
```

**Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "enforcement-mcp": {
      "command": "enforcement-mcp",
      "args": ["serve", "webserver01.example.com"]
    }
  }
}
```

### Daily use

Talk to your AI assistant in natural language:

| You say | What happens |
|---------|-------------|
| "Why can't httpd serve files from /home?" | `troubleshoot` → finds AVC denial → `denial_explain` → suggests boolean fix |
| "Generate a playbook to fix that" | `generate_playbook` → ranked Ansible playbooks with risk scores |
| "Show me the security posture" | `host_posture` → 0-100 score with findings |
| "Are we exposed to CVE-2024-6387?" | `cve_exposure` → ATT&CK chain mapped against current policy |
| "Enable that boolean, it's low risk" | `set_boolean` with `dry_run=false` → applied + verified |
| "New binary in /opt won't execute" | `fapolicyd_trust_check` → not trusted → `generate_playbook` or `fapolicyd_trust_add` |

### Multi-host: switching targets per call

Every SSH-connected tool accepts an optional `target` parameter.
Point at any host without restarting the server:

```json
{
  "tool": "diagnosis.host_posture",
  "arguments": {
    "target": "webserver01.example.com"
  }
}
```

Then check a different host in the same session:

```json
{
  "tool": "diagnosis.host_posture",
  "arguments": {
    "target": "dbserver02.example.com"
  }
}
```

Target formats:

| Format | Example |
|--------|---------|
| Hostname | `webserver01.example.com` |
| User@host | `admin@webserver01.example.com` |
| Host:port | `webserver01.example.com:2222` |
| User@host:port | `admin@webserver01.example.com:2222` |

SSH credentials (user, port, key file) come from environment variables
for any parts not specified in the target string. Connections are pooled —
the server reuses an existing SSH connection when the same target is used again.

If you omit `target`, the server uses its default (from CLI `--target` arg
or `ENFORCEMENT_MCP_TARGET` env var).

### Offline mode: analyzing log files

You don't need SSH to diagnose denials from log files. Three approaches:

**1. Parse raw denial text (any source)**

Feed `ausearch` output, raw `audit.log` lines, or SIEM-exported records
directly to `parse_denials`:

```json
{
  "tool": "diagnosis.parse_denials",
  "arguments": {
    "raw_text": "type=AVC msg=audit(1697051234.567:890): avc:  denied  { read } for  pid=1234 comm=\"httpd\" name=\"index.html\" dev=\"sda1\" ino=56789 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0"
  }
}
```

Returns structured JSON with parsed fields, summary statistics, and
auto-detection of AVC vs FANOTIFY denial types.

**2. Troubleshoot from log text (full diagnosis)**

For a complete diagnosis — root cause, explanation, and fix suggestions —
pass log text to `troubleshoot`:

```json
{
  "tool": "diagnosis.troubleshoot",
  "arguments": {
    "symptom": "httpd blocked from serving user home directories",
    "raw_avc_text": "type=AVC msg=audit(...): avc:  denied  { read } for  pid=1234 comm=\"httpd\" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file"
  }
}
```

This runs the full troubleshooting pipeline offline — root cause analysis,
boolean detection, fix alternatives — without SSH.

**3. Feed denial-specific tools**

`avc_denials` and `fapolicyd_denials` also accept `raw_text` for offline parsing:

```json
{
  "tool": "diagnosis.avc_denials",
  "arguments": {
    "raw_text": "<paste audit.log content or ausearch output here>"
  }
}
```

**Getting the log data:**

```bash
# Grab recent AVC denials from a host
ssh root@webserver01 'ausearch -m AVC -ts recent' > /tmp/denials.txt

# Or from audit.log directly
ssh root@webserver01 'grep "avc:  denied" /var/log/audit/audit.log' > /tmp/denials.txt

# Or from journalctl (fapolicyd)
ssh root@webserver01 'journalctl -u fapolicyd --since "1 hour ago"' > /tmp/denials.txt
```

Then paste the contents as `raw_text` or `raw_avc_text`. An agent with
access to both a log aggregator MCP (Splunk, ELK, Loki) and enforcement-mcp
can pull denials from the aggregator and analyze them without ever
touching the target host.

## Safety model

- **Diagnosis tools** run without root and never modify the system
- **Playbook generation** produces YAML text output only — never executes playbooks
- **Management tools** default to `dry_run=true` — they show you what would happen
- **Risk assessment** runs automatically before every mutation
- **Critical risk changes** (score 76-100) are hard-blocked
- **Root MLS range restriction** is permanently blocked (lockout protection)
- Every change is reversible and the reversal command is included in the response
- **Identity verification** optional but recommended for multi-agent deployments
