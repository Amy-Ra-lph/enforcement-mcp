# Non-Frontier Model Testing: Goose + Ollama + Qwen3

**Date:** 2026-10-27
**Tester:** Amy Ralph (afarley)
**Triggered by:** pbuchan feedback — uses qwen + goose in air-gapped lab for customer demos

## Test Environment

| Component | Version | Location |
|-----------|---------|----------|
| enforcement-mcp | v0.5.1 | MCP server host, port 8402, streamable-http transport |
| Goose | v1.56.0 | Client host |
| Ollama | latest | Client host, CPU-only |
| qwen3:0.6b | 522 MB | Ollama on client host |
| qwen3:1.7b | 1.4 GB | Ollama on client host |

**Hardware:** 22 vCPUs (AMD EPYC-Rome), 3.8 GB RAM, no GPU. RHEL 10 (Fedora 44).

## Setup Issues

### IPv6 Routing (Cloudflare R2)

Ollama model pull failed silently. Cloudflare R2 storage resolved to IPv6 addresses. The lab network has no IPv6 route.

**Error:** `dial tcp [2606:4700:2ff9::1]:443: connect: no route to host`

**Fix:**
```bash
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
```

Go's DNS resolver ignores `/etc/gai.conf` IPv4 preference. Kernel-level disable is required.

### Goose Extension Configuration

Goose v1.56.0 dropped SSE transport support. The `config.yaml` `extensions:` block loaded the MCP connection (server logs showed 200/202 from IDM node) but did not inject tools into the model prompt.

**Working configuration:** CLI flags only.

```bash
goose run \
  --provider ollama \
  --model qwen3:1.7b \
  --with-streamable-http-extension 'http://<mcp-server-host>:8402/mcp' \
  --no-profile \
  --text - \
  --max-turns 3
```

- `--with-streamable-http-extension` injects MCP tools into the model context.
- `--no-profile` prevents goose built-in extensions from inflating the tool count.
- Without `--no-profile`, 17 built-in tools load alongside 30 enforcement-mcp tools (47 total).

## Results

### MCP Protocol: PASS

All 30 enforcement-mcp tools loaded into goose via streamable-http. The MCP handshake, tool listing, and tool invocation protocol work correctly. Tool calls reach the server. Responses return to goose.

### qwen3:0.6b (522 MB): FAIL — No Tool Calls

The model acknowledged the prompt but did not generate any tool calls. Output:

> "None of the provided tools can be used in the current context."

The 0.6b model cannot perform structured tool calling with 47 tools in context.

### qwen3:1.7b (1.4 GB): PARTIAL — Wrong Tools, Hallucinated Params

The model generated valid tool call JSON. The structured output format is correct. The model selected wrong tools and fabricated parameters.

**Prompt:** "Use the enforcement-mcp diagnosis.host_posture tool to check SELinux status on target localhost."

**Expected:** One call to `diagnosis.host_posture` with `target=localhost`.

**Actual:** Four calls to management (mutating) tools:

| Tool Called | Parameters | Result |
|-------------|-----------|--------|
| `manage.fapolicyd_trust_add` | `path=/opt/myapp/bin/worker` | `file_not_found` error |
| `manage.generate_module` | `name=httpd_homedir_fix, from_denials=1h` | `no_denials` (no AVC denials found) |
| `manage.load_module` | `name=httpd_homedir_fix` (missing required `cil` param) | Pydantic validation error |
| `manage.set_boolean` | `name=httpd_enable_homedirs, value=true` | **Executed successfully.** Returned SELinux state change preview. |

**Observations:**

1. The model ignored the explicit tool name in the prompt.
2. All four tools are `manage.*` (Tier 3, mutating). None are `diagnosis.*` (Tier 1, read-only).
3. Parameter values (`/opt/myapp/bin/worker`, `httpd_homedir_fix`) appear to come from training data, not the prompt or host state.
4. `set_boolean` returned a real SELinux state change preview with `status: preview` because `dry_run` defaults to `true`. If `dry_run` defaulted to `false`, the model would have changed SELinux policy.

### Explicit Tool Name in Prompt: FAIL

A second test used the full goose-mangled tool name:

**Prompt:** "Call the tool named enforcement-mcp__diagnosis_host_posture_f6dc9b06 with argument target set to the string localhost."

**Result:** Same behavior. The model called four `manage.*` tools with hallucinated parameters.

### Custom Modelfile (Thinking Disabled): FAIL

A custom ollama modelfile disabled thinking mode and added a system prompt constraining tool selection. The model still called wrong tools.

## Safety Finding

The 1.7b model called mutating management tools when asked for read-only diagnosis. One call (`set_boolean httpd_enable_homedirs on`) executed successfully against the live SELinux policy on the target host.

**Current mitigations:**
- `dry_run=true` default on all management tools prevented actual policy mutation.
- The `strict` authz mode with identity verification blocks anonymous `manage.*` calls.

**Gap:** The default deployment mode (`permissive` authz, no identity) exposes all 30 tools without authentication. A non-frontier model connected to this configuration can mutate SELinux policy, load CIL modules, and modify fapolicyd trust lists.

## Recommendations

### 1. Tool-Tier System (ENFORCEMENT_MCP_TOOL_TIER)

Register tools by tier. Default to `diagnosis` when no auth is configured.

| Tier | Value | Tools Registered | Use Case |
|------|-------|-----------------|----------|
| diagnosis | `diagnosis` | 18 read-only tools | Air-gapped, non-frontier models, customer demos |
| remediation | `remediation` | 19 tools (diagnosis + generate_playbook) | Guided remediation with human review |
| management | `management` | 30 tools (all) | Frontier models with auth + identity |

**Environment variable:** `ENFORCEMENT_MCP_TOOL_TIER=diagnosis|remediation|management`

**Default behavior:**
- If `ENFORCEMENT_MCP_AUTHZ_POLICY=strict` and identity is configured: `management`
- If `ENFORCEMENT_MCP_AUTHZ_POLICY=permissive` or no identity: `diagnosis`

### 2. Secure-by-Default Authz

Make `strict` + identity `none` the default configuration. This gives a clean diagnosis-only mode. Require explicit opt-in for `manage.*` tools. (Aligns with pbuchan hardening suggestion #2.)

### 3. Documentation

Add a "Non-Frontier Model Deployment" section to QUICKSTART.md:
- Recommended: `ENFORCEMENT_MCP_TOOL_TIER=diagnosis`
- Warn against `--host 0.0.0.0` without auth
- Minimum model size: 7B+ parameters for reliable tool selection
- 1.7B: MCP protocol works, tool selection unreliable
- 0.6B: cannot perform tool calling

## Appendix: Goose Log Excerpt

Tool list injected into qwen3:1.7b (47 tools, 30 from enforcement-mcp):

```
enforcement-mcp__diagnosis_active_containments
enforcement-mcp__diagnosis_avc_denials
enforcement-mcp__diagnosis_boolean_list
enforcement-mcp__diagnosis_cve_exposure
enforcement-mcp__diagnosis_denial_explain
enforcement-mcp__diagnosis_fapolicyd_denials
enforcement-mcp__diagnosis_fapolicyd_rules
enforcement-mcp__diagnosis_fapolicyd_status
enforcement-mcp__diagnosis_fapolicyd_trust_check
enforcement-mcp__diagnosis_file_context
enforcement-mcp__diagnosis_generate_playbook
enforcement-mcp__diagnosis_host_posture
enforcement-mcp__diagnosis_mls_categories
enforcement-mcp__diagnosis_mls_file_level
enforcement-mcp__diagnosis_mls_user_mappings
enforcement-mcp__diagnosis_parse_denials
enforcement-mcp__diagnosis_policy_query
enforcement-mcp__diagnosis_troubleshoot
enforcement-mcp__manage_assess_risk
enforcement-mcp__manage_containment_expire
enforcement-mcp__manage_cve_contain
enforcement-mcp__manage_fapolicyd_trust_add
enforcement-mcp__manage_fapolicyd_trust_remove
enforcement-mcp__manage_generate_module
enforcement-mcp__manage_load_module
enforcement-mcp__manage_mls_assign_category
enforcement-mcp__manage_mls_set_user_range
enforcement-mcp__manage_remove_module
enforcement-mcp__manage_set_boolean
enforcement-mcp__manage_set_file_context
```
