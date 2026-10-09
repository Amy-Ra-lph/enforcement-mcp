# enforcement-mcp

SELinux, fapolicyd, and MLS policy intelligence MCP server for LLM agents.

Diagnose why applications are blocked by security policy. Assess risk before
changes. Contain CVEs with targeted, reversible policy. Structured JSON output
for every operation — no more guessing what `audit2allow` means.

**New here?** See the [Getting Started guide](docs/QUICKSTART.md) for a hands-on walkthrough.

## Quick Start

```bash
# Install from GitHub
pip install git+https://github.com/Amy-Ra-lph/enforcement-mcp.git

# Auto-configure your MCP client + verify the target host
enforcement-mcp setup webserver01.example.com
enforcement-mcp check webserver01.example.com

# Or run directly
export ENFORCEMENT_MCP_TARGET=myhost.example.com
enforcement-mcp

# Container deployment
podman run -i --rm \
  -e ENFORCEMENT_MCP_TARGET=myhost.example.com \
  -v ~/.ssh/id_ed25519:/opt/app-root/src/.ssh/id_ed25519:ro \
  quay.io/rhel-security/enforcement-mcp
```

### Configuration

| Environment Variable | Required | Default | Description |
|---------------------|----------|---------|-------------|
| `ENFORCEMENT_MCP_TARGET` | Yes | — | Remote RHEL host to analyze (alias: `ENFORCEMENT_MCP_HOST`) |
| `ENFORCEMENT_MCP_USER` | No | `root` | SSH user |
| `ENFORCEMENT_MCP_PORT` | No | `22` | SSH port |
| `ENFORCEMENT_MCP_KEY_FILE` | No | — | SSH private key (uses SSH agent if unset) |

## Tools

29 tools across three permission tiers. All return structured JSON.

### Diagnosis (no root, read-only)

Use `diagnosis.troubleshoot` as the primary entry point when something is blocked.

| Tool | Description |
|------|-------------|
| `diagnosis.troubleshoot` | Composite diagnosis across SELinux + fapolicyd + DAC |
| `diagnosis.host_posture` | Security posture summary with 0-100 score |
| `diagnosis.avc_denials` | Recent SELinux AVC denials, parsed and structured |
| `diagnosis.policy_query` | Query SELinux allow rules for a source type |
| `diagnosis.boolean_list` | SELinux booleans with current state |
| `diagnosis.file_context` | Expected vs actual file context (detects mismatches) |
| `diagnosis.denial_explain` | Explain why a denial happened (boolean, no_rule, constraint) |
| `diagnosis.fapolicyd_status` | fapolicyd daemon status, rule count, trust DB size |
| `diagnosis.fapolicyd_denials` | Recent fapolicyd FANOTIFY denials |
| `diagnosis.fapolicyd_trust_check` | Check if a binary is trusted |
| `diagnosis.fapolicyd_rules` | Current fapolicyd rule set |
| `diagnosis.mls_user_mappings` | User-to-SELinux-user MLS/MCS mappings |
| `diagnosis.mls_file_level` | MLS level and categories of a file or process |
| `diagnosis.mls_categories` | Defined MLS sensitivities and categories |
| `diagnosis.cve_exposure` | Assess policy against a CVE's exploit chain (ATT&CK mapping) |
| `diagnosis.active_containments` | List temporary CVE containment modules with patch status |
| `diagnosis.parse_denials` | Parse raw AVC/FANOTIFY text into structured JSON — no SSH needed |

### Offline / Log Aggregator Mode

Several diagnosis tools accept raw text input, enabling analysis without a live SSH
connection. Use with Splunk, ELK, Loki, or raw audit.log exports:

- `diagnosis.parse_denials` — pure offline, accepts raw denial text, returns structured JSON with summary statistics
- `diagnosis.avc_denials(raw_text=...)` — parse AVC denials from text instead of SSH
- `diagnosis.fapolicyd_denials(raw_text=...)` — parse FANOTIFY denials from text
- `diagnosis.troubleshoot(raw_avc_text=..., raw_fanotify_text=...)` — offline root cause analysis

### Management (mutating, risk-gated)

All management tools default to `dry_run=true` (preview only). Set `dry_run=false`
to apply. Every mutation runs `assess_risk` first. Critical-risk changes are blocked.

| Tool | Description |
|------|-------------|
| `manage.assess_risk` | Pre-change risk assessment (0-100 score) |
| `manage.set_boolean` | Toggle an SELinux boolean |
| `manage.generate_module` | Generate CIL module from observed denials |
| `manage.load_module` | Load a CIL policy module |
| `manage.remove_module` | Remove a loaded policy module |
| `manage.set_file_context` | Add persistent file context rule + relabel |
| `manage.fapolicyd_trust_add` | Add binary to fapolicyd trust (checks setuid, location) |
| `manage.fapolicyd_trust_remove` | Remove binary from fapolicyd trust |
| `manage.mls_assign_category` | Assign MLS categories to files |
| `manage.mls_set_user_range` | Modify user MLS range (hard-blocks root restriction) |
| `manage.cve_contain` | Generate targeted CVE containment with risk assessment |
| `manage.containment_expire` | Safe containment removal after patch verified |

## Risk Scoring

Every mutation is scored 0-100 before execution:

| Score | Level | Behavior |
|-------|-------|----------|
| 0-25 | Low | Proceed with confirmation |
| 26-50 | Medium | Show alternatives, confirm |
| 51-75 | High | Recommend alternative, require override |
| 76-100 | Critical | Hard block |

Scoring factors: blast radius, permission severity, target sensitivity,
reversibility, least privilege gap, lockout potential.

## CVE Containment Pipeline

```
CVE ID → Red Hat Security Data API → CWE → ATT&CK techniques
→ SELinux permissions per exploit step → check current policy
→ generate targeted CIL containment → risk assess → apply
→ auto-expire when patched RPM installed
```

## Identity & Authorization

Management tools accept an optional `identity_token` parameter for RBAC enforcement.
Supports OAuth 2.0 (JWT) and SPIFFE workload identity.

### Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `ENFORCEMENT_MCP_IDENTITY_MODE` | `none` | `none`, `oauth`, `spiffe`, or `both` |
| `ENFORCEMENT_MCP_AUTHZ_POLICY` | `permissive` | `permissive` (log only) or `strict` (enforce) |
| `ENFORCEMENT_MCP_OAUTH_ISSUER` | — | OAuth issuer URL (e.g. Keycloak realm) |
| `ENFORCEMENT_MCP_OAUTH_AUDIENCE` | — | Expected JWT audience |
| `ENFORCEMENT_MCP_OAUTH_JWKS_URI` | — | JWKS endpoint for signature verification |
| `ENFORCEMENT_MCP_SPIFFE_TRUST_DOMAIN` | — | SPIFFE trust domain |
| `ENFORCEMENT_MCP_SPIFFE_SOCKET` | — | SPIFFE Workload API socket path |
| `ENFORCEMENT_MCP_SSH_HOST_KEY_POLICY` | `warn` | SSH host key policy: `warn`, `reject`, or `auto` |

### Roles

| Role | Access |
|------|--------|
| `admin` | All tools |
| `operator` | Management tools (except MLS user range) |
| `viewer` | Diagnosis only |
| `containment` | CVE containment + diagnosis + risk assessment |

Roles are extracted from JWT claims (`roles` or `realm_access.roles`) or
SPIFFE ID path segments (`spiffe://domain/operator/agent-name`).

### Audit Trail

Every tool invocation is logged to `/var/lib/enforcement-mcp/audit.jsonl` on
the remote host. Entries include caller identity, tool name, parameters
(tokens redacted), risk score, and authorization decision.

## Development

```bash
# Install dev dependencies
uv sync --extra dev

# Run tests (322 tests)
uv run pytest tests/ -v

# Lint
uv run ruff check src/ tests/

# Type check
uv run mypy src/
```

## Architecture

- **Python 3.12** + FastMCP + Paramiko SSH + Pydantic + PyJWT (optional)
- **SSH-proxy mode**: Zero-install diagnosis on any RHEL host
- **Three tiers**: diagnosis (free) → diagnosis-elevated (root/read-only) → manage (root/mutating)
- **Identity**: OAuth 2.0 JWT + SPIFFE SVID verification with role-based access control
- **Audit**: JSONL audit trail on remote host with token redaction
- **CVE data**: Direct Red Hat Security Data API (no auth required)
- **Input sanitization**: All tool parameters validated before shell execution ([threat model](docs/THREAT-MODEL.md))
- **Transport-agnostic**: Tool implementations are pure functions, transport is separate

## CLI Commands

```bash
# Auto-configure Claude Code, Claude Desktop, or Cursor
enforcement-mcp setup webserver01.example.com

# Verify target host has required packages (setools, audit, etc.)
enforcement-mcp check webserver01.example.com

# Run the MCP server (default)
enforcement-mcp serve
enforcement-mcp serve --transport sse --port 8100
```

## License

Apache-2.0
