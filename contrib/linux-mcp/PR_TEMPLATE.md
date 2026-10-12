# PR: Add SPIFFE/WID identity + remediation playbook generation

## Summary

- Add SPIFFE workload identity as a fifth auth provider alongside Google,
  GitHub, JWT, and Introspection
- Add SELinux remediation playbook generator using `fedora.linux_system_roles`
- All new tools are `readOnlyHint=True` — no system mutations
- Risk scoring included with every generated playbook

## What's included

### Identity (SPIFFE/WID)
- `identity/spiffe.py` — SPIFFE ID verification with trust domain validation
- `identity/wid.py` — Workload Identity Document layer (extends SPIFFE)
- `auth_spiffe.py` — FastMCP auth provider adapter (plugs into existing auth.py)
- Claims output matches existing JWT format → `auth_policy.yaml` rules work unchanged

### Remediation
- `tools/selinux_remediate.py` — Playbook generator for 4 finding types:
  - `denial`: relabel → boolean → custom CIL module (ranked by risk)
  - `file_context`: restorecon → permanent fcontext rule
  - `fapolicyd_block`: trust path addition
  - `aide_change`: investigate (management deferred to enforcement-mcp)

### Config changes
- `AuthProvider.SPIFFE` added to enum
- `SPIFFEAuthConfig` settings class
- `selinux_sesearch_boolean` command spec

## Security review

All input validated:
- SELinux identifiers: `^[a-zA-Z_][a-zA-Z0-9_.\-]*$`
- Paths: existing `validate_path()`
- Shell args: `shlex.quote()` on all sesearch parameters
- Playbook output: `yaml.dump()` (no raw string interpolation)

Command injection audit:
- Single SSH command (`sesearch`) with all parameters shell-escaped
- No `f"..."` strings in shell commands without `shlex.quote()`

## Required reviewers

- [ ] **@bsmithgit** — linux-mcp maintainer, architecture + auth integration
- [ ] **@lvrabec** — SELinux dev team lead, policy correctness
- [ ] SELinux dev team — CIL module generation, boolean lookup logic,
      risk scoring thresholds for SELinux-specific operations
- [ ] **@afarley** — enforcement-mcp maintainer, identity/WID design

## Review focus areas for SELinux team

1. **CIL module generation** (`selinux_remediate.py:_remediate_denial`):
   Is `(allow {source} {target} ({tclass} ({permission})))` the right CIL
   for single-rule modules? Should we set a different priority than 400?

2. **Boolean lookup** (`sesearch --allow -s ... -t ... -c ... -p ... -b`):
   Is this the correct sesearch invocation? Are there edge cases where
   sesearch returns booleans that wouldn't actually fix the denial?

3. **Risk scoring thresholds**: `SENSITIVE_TYPES` list (shadow_t=30,
   sshd_key_t=30, etc.) and `HIGH_RISK_PERMISSIONS` (execmem=20,
   relabelto=25, etc.) — are these reasonable defaults?

4. **Relabel safety**: We score restorecon at risk=0 (safest). Is there
   any scenario where restorecon could be destructive?

## Test plan

- [ ] All existing linux-mcp tests pass (`make verify`)
- [ ] SPIFFE ID verification: valid domain, wrong domain, malformed ID
- [ ] WID claims: role extraction from path segments
- [ ] Auth policy: SPIFFE claims match existing PolicyRule format
- [ ] Remediation: all 4 finding types produce valid YAML
- [ ] Remediation: input validation rejects shell injection attempts
- [ ] Remediation: alternatives sorted by risk score ascending
- [ ] sesearch integration: graceful fallback when setools not installed
