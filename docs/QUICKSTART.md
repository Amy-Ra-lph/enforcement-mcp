# Getting Started with enforcement-mcp

Get from zero to diagnosing SELinux denials in under 5 minutes.

## Prerequisites

- A RHEL 9 or 10 host with SSH access (key-based auth)
- Python 3.12+ on your local machine (or use the container)
- `setools-console` installed on the target host (`dnf install -y setools-console`)

## 1. Install and configure

```bash
# Clone and install
git clone https://github.com/Amy-Ra-lph/enforcement-mcp.git
cd enforcement-mcp
pip install -e .

# Point at your RHEL host
export ENFORCEMENT_MCP_HOST=myhost.example.com
export ENFORCEMENT_MCP_USER=root           # default
export ENFORCEMENT_MCP_KEY_FILE=~/.ssh/id_ed25519  # optional
```

Or use `uv`:

```bash
uv sync
uv run enforcement-mcp
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

## 5. Apply the fix

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

## 6. Check your security posture

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

## 7. CVE containment (when a patch isn't ready yet)

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
| "Why is my app blocked?" | `troubleshoot` → `denial_explain` → `set_boolean` or `generate_module` |
| "Is this host hardened?" | `host_posture` |
| "What does this boolean do?" | `assess_risk` with `change_type=boolean` |
| "New binary won't run" | `fapolicyd_trust_check` → `fapolicyd_trust_add` |
| "CVE dropped, no patch yet" | `cve_exposure` → `cve_contain` → `containment_expire` (after patch) |
| "Need a custom policy module" | `generate_module` → review CIL → `load_module` |

## MCP client configuration

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "enforcement-mcp": {
      "command": "uvx",
      "args": ["enforcement-mcp"],
      "env": {
        "ENFORCEMENT_MCP_HOST": "myhost.example.com"
      }
    }
  }
}
```

### Claude Code

Add to your MCP settings or `.mcp.json`:

```json
{
  "enforcement-mcp": {
    "command": "uvx",
    "args": ["enforcement-mcp"],
    "env": {
      "ENFORCEMENT_MCP_HOST": "myhost.example.com"
    }
  }
}
```

## Safety model

- **Diagnosis tools** run without root and never modify the system
- **Management tools** default to `dry_run=true` — they show you what would happen
- **Risk assessment** runs automatically before every mutation
- **Critical risk changes** (score 76-100) are hard-blocked
- **Root MLS range restriction** is permanently blocked (lockout protection)
- Every change is reversible and the reversal command is included in the response
