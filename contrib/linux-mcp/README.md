# linux-mcp Upstream Contribution

Files in this directory are structured for contribution to
[linux-mcp-server](https://github.com/bsmithgit/linux-mcp-server). They extend
linux-mcp with:

1. **SPIFFE/WID identity** — workload identity verification for agentic deployments
2. **Remediation playbook generation** — Ansible playbooks using linux-system-roles
3. **Risk scoring** — 0-100 risk assessment for security policy changes
4. **Enhanced SELinux tools** — denial explanation, policy query, offline parsing

## File Mapping

```
contrib/linux-mcp/                    →  linux-mcp-server/src/linux_mcp_server/
├── identity/
│   ├── spiffe.py                     →  identity/spiffe.py (NEW)
│   ├── wid.py                        →  identity/wid.py (NEW)
│   └── models.py                     →  identity/models.py (NEW)
├── tools/
│   ├── selinux_remediate.py          →  tools/selinux_remediate.py (NEW)
│   ├── selinux_enhanced.py           →  tools/selinux_enhanced.py (NEW)
│   └── risk.py                       →  tools/risk.py (NEW)
├── parsers/
│   ├── selinux_cli.py                →  parsers/selinux_cli.py (NEW)
│   └── _hardening.py                 →  parsers/_hardening.py (NEW)
├── auth_spiffe.py                    →  auth_spiffe.py (NEW, extends auth.py)
└── config_extensions.py              →  config additions
```

## Integration with linux-mcp Auth

linux-mcp already supports Google, GitHub, JWT, and Introspection auth via
FastMCP's `RemoteAuthProvider`. This contribution adds SPIFFE as a fifth
provider type, extending the existing `AuthProvider` enum and `AuthConfig`.

SPIFFE identity maps to linux-mcp's existing policy rules via claims:
- `spiffe://domain/admin/*` → claims include `role: admin`
- `spiffe://domain/operator/*` → claims include `role: operator`

This means existing `auth_policy.yaml` rules work unchanged — SPIFFE identities
surface the same claim structure as JWT tokens.

## Dependencies Added

- `enforcement-mcp-parsers` (pydantic only, zero other deps)
- `PyYAML` (already a linux-mcp dep)
- `PyJWT[crypto]` (optional, only for SPIFFE X.509 SVID verification)

## How to Test

```bash
# From linux-mcp-server root
uv sync
uv run pytest tests/tools/test_selinux_remediate.py -v
uv run pytest tests/identity/ -v
```

## Safety

- All new tools are `readOnlyHint=True` (matches linux-mcp convention)
- Playbook generation returns YAML text, never executes
- Input validation via sanitizers (same as existing `validate_path`)
- Risk scoring is advisory output, not access control
