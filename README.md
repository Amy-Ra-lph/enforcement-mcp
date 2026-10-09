# enforcement-mcp

SELinux, fapolicyd, and MLS policy intelligence MCP server for LLM agents.

Diagnose why applications are blocked by security policy. Structured JSON output
for every query — no more guessing what `audit2allow` means.

## Quick Start

```bash
# Set target host
export ENFORCEMENT_MCP_HOST=myhost.example.com

# Run via uvx
uvx enforcement-mcp

# Run via container
podman run -i --rm \
  -e ENFORCEMENT_MCP_HOST=myhost.example.com \
  -v ~/.ssh/id_ed25519:/app/.ssh/id_ed25519:ro \
  quay.io/enforcement-mcp/enforcement-mcp
```

## Tools

All tools return structured JSON. Use `diagnosis.troubleshoot` as the primary
entry point when something is blocked.

| Tool | Description |
|------|-------------|
| `diagnosis.troubleshoot` | Composite diagnosis across SELinux + fapolicyd + DAC |
| `diagnosis.host_posture` | Security posture summary with 0-100 score |
| `diagnosis.avc_denials` | Recent SELinux AVC denials |
| `diagnosis.policy_query` | Query SELinux allow rules |
| `diagnosis.boolean_list` | SELinux booleans with state |
| `diagnosis.file_context` | Expected vs actual file context |
| `diagnosis.denial_explain` | Explain why a denial happened |
| `diagnosis.fapolicyd_status` | fapolicyd daemon status |
| `diagnosis.fapolicyd_denials` | Recent fapolicyd denials |
| `diagnosis.fapolicyd_trust_check` | Check binary trust status |
| `diagnosis.fapolicyd_rules` | Current fapolicyd rules |
| `diagnosis.mls_user_mappings` | User-to-SELinux-user MLS mappings |
| `diagnosis.mls_file_level` | MLS level of file or process |
| `diagnosis.mls_categories` | Defined MLS categories |

## Status

Phase 1: Diagnosis PoC — SSH-proxy mode, read-only tools.

## License

Apache-2.0
