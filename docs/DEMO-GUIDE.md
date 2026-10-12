# Demo Guide: enforcement-mcp + linux-mcp

How to demo the full enforcement-mcp toolset and the linux-mcp upstream
integration. Two demo tracks: **standalone enforcement-mcp** (30 tools,
full stack) and **linux-mcp with enforcement-mcp extensions** (read-only
diagnosis + remediation + SPIFFE/WID identity).

## Prerequisites

### Target host

- RHEL 9 or 10 with SSH root access (key-based)
- Packages: `setools-console`, `audit`, `policycoreutils-python-utils`
- Optional: `fapolicyd`, `aide` (for those demo acts)
- The Beaker lab VMs work (`/poc-lab` to provision fresh ones)

### Demo machine (your laptop)

```bash
# Option A: pip install
pip install git+https://github.com/Amy-Ra-lph/enforcement-mcp.git

# Option B: container
podman pull quay.io/rhel-security/enforcement-mcp:main
```

### MCP client configuration

```bash
# Auto-configure Claude Code / Claude Desktop / Cursor
enforcement-mcp setup <target-host>
enforcement-mcp check <target-host>
```

### For linux-mcp demo track

```bash
# Brian Smith's linux-mcp (separate install)
pip install git+https://github.com/bsmithgit/linux-mcp-server.git
```

---

## Demo Track 1: enforcement-mcp (Full Stack)

**Audience:** Security architects, SRE leads, compliance teams
**Duration:** 15-20 minutes
**Message:** "AI agents can diagnose, assess, and remediate security policy —
safely, with risk scoring and human-in-the-loop"

### Act 1: Diagnosis — "Why is my app blocked?"

**Setup:** httpd installed, SELinux enforcing, UserDir enabled in httpd.conf
but `httpd_enable_homedirs` boolean off. Create `/home/testuser/public_html/index.html`.

```
→ "Why can't httpd serve files from /home/testuser/public_html?"
```

Show: `diagnosis.troubleshoot` finds SELinux AVC denial, rules out fapolicyd
and DAC. Structured JSON output — no `ausearch | audit2allow` guesswork.

**Key point:** Single question, composite diagnosis across 3 subsystems.

### Act 2: Explanation — "What exactly is blocking it?"

```
→ "Explain that denial"
```

Show: `diagnosis.denial_explain` identifies the boolean `httpd_enable_homedirs`,
shows it's currently off, explains why the denial happened.

**Key point:** Root cause in plain English, not raw audit log.

### Act 3: Risk Assessment — "How risky is the fix?"

```
→ "What's the risk of enabling that boolean?"
```

Show: `manage.assess_risk` returns score 18/100 (low), blast radius (3 rules
unlocked, only httpd_t affected), rollback command included.

**Key point:** Quantified risk before any change. 0-100 score with
actionable levels.

### Act 4: Remediation Playbook — "Give me an Ansible playbook" ★ NEW

```
→ "Generate a remediation playbook for that denial"
```

Show: `diagnosis.generate_playbook` returns **3 ranked alternatives**:

| # | Strategy | Risk | Scope |
|---|----------|------|-------|
| 1 | Relabel file | 0/100 | Narrowest — no policy change |
| 2 | Toggle boolean | 18/100 | Medium — enables 3 rules |
| 3 | Custom CIL module | 5/100 | Narrow — single allow rule |

Each includes complete Ansible YAML using `fedora.linux_system_roles.selinux`
with risk assessment in the header comments.

**Key point:** Generate-only, never executes. Human reviews risk + playbook
before applying. Safest option recommended first.

### Act 5: Apply the Fix

```
→ "Enable the boolean, it's low risk"
```

Show: `manage.set_boolean` with `dry_run=false`. Applied + verified.

**Key point:** dry_run=true default. Explicit opt-in to mutation.

### Act 6: fapolicyd — "New binary won't run"

**Setup:** Copy a binary to `/opt/myapp/bin/worker`. fapolicyd active.

```
→ "Why can't /opt/myapp/bin/worker execute?"
→ "Generate a playbook to trust it"
```

Show: `diagnosis.fapolicyd_trust_check` → not trusted.
`diagnosis.generate_playbook(fapolicyd_block)` → playbook using
`fedora.linux_system_roles.fapolicyd` with risk score.

**Key point:** Same workflow for fapolicyd as SELinux. Risk scoring
flags `/tmp` paths as high-risk.

### Act 7: Security Posture — "Show me the big picture"

```
→ "What's the security posture of this host?"
```

Show: `diagnosis.host_posture` → 0-100 score with findings
(SELinux mode, denial count, fapolicyd status, custom modules).

**Key point:** Single-call health check across all subsystems.

### Act 8: CVE Containment — "CVE dropped, no patch yet"

```
→ "Are we exposed to CVE-2024-6387?"
→ "Generate containment while we wait for the patch"
```

Show: `diagnosis.cve_exposure` → ATT&CK chain mapped against current policy.
`manage.cve_contain` → targeted CIL containment with risk assessment.
`manage.containment_expire` → safe removal after patch verified.

**Key point:** Automated CVE-to-policy pipeline. Containment is temporary
and auto-expires.

### Act 9: Offline Mode — "Analyze logs from Splunk"

```
→ "Parse these denial logs" (paste raw AVC text)
```

Show: `diagnosis.parse_denials` → structured JSON from raw text. No SSH
needed. Works with Splunk, ELK, Loki exports.

**Key point:** Useful even without live host access.

### Act 10: Architecture Slide

Show the three-tier diagram:

```
┌──────────────────────────────────────────────┐
│  Tier 1: Diagnosis (read-only, no auth)      │
│  troubleshoot, denials, posture, explain...  │
├──────────────────────────────────────────────┤
│  Tier 2: Remediation (read-only output)  ★   │
│  generate_playbook → Ansible YAML + risk     │
├──────────────────────────────────────────────┤
│  Tier 3: Management (mutating, auth+RBAC)    │
│  set_boolean, load_module, cve_contain...    │
└──────────────────────────────────────────────┘
```

**Key point:** Tier 1+2 safe for upstream (linux-mcp). Tier 3 stays in
enforcement-mcp with identity verification + audit trail.

---

## Demo Track 2: linux-mcp + enforcement-mcp Extensions

**Audience:** Brian Smith, linux-mcp contributors, platform engineering teams
**Duration:** 10-12 minutes
**Message:** "linux-mcp gains SELinux remediation and workload identity
without taking on management-tier risk"

### Act 1: Current linux-mcp SELinux Tools

Show what linux-mcp has today:

```
→ "Show me SELinux status"        → get_selinux_status
→ "List SELinux booleans"         → get_selinux_booleans
→ "Show file context for /var/www" → get_selinux_file_context
→ "Show recent AVC denials"       → get_selinux_denials
→ "Show SELinux port types"        → get_selinux_ports
```

**Key point:** 5 read-only tools. Diagnosis only. No remediation, no risk
scoring, no explanation.

### Act 2: What's Missing — The Gap

Demonstrate the gap:

```
→ "httpd is getting AVC denials — what should I do?"
```

linux-mcp shows the denials but can't explain them, assess risk, or suggest
fixes. The sysadmin is on their own from here.

### Act 3: With enforcement-mcp Extensions

Same scenario, now with the contributed tools:

```
→ "Generate a remediation playbook for this denial"
```

Show: `generate_selinux_playbook` returns ranked Ansible playbooks with risk
scores. All `readOnlyHint=True`. Uses linux-mcp's existing `Host` type,
`@log_tool_call`, `validate_path()`.

**Key point:** Fits linux-mcp's architecture. No new patterns introduced.

### Act 4: SPIFFE/WID Identity

Show workload identity for agentic deployments:

```yaml
# auth_policy.yaml (linux-mcp's existing format)
rules:
  - host: "webserver*"
    tools: ["*"]
    claims:
      role: operator
      trust_domain: example.com
    action: ssh_default
```

```
→ Agent authenticates with: spiffe://example.com/operator/sre-agent
→ Claims extracted: {role: operator, trust_domain: example.com}
→ Policy rule matches → access granted
```

**Key point:** SPIFFE claims map to existing `auth_policy.yaml`. No new
policy format. Extends the provider list alongside Google/GitHub/JWT.

### Act 5: What Stays in enforcement-mcp

Show the boundary:

| linux-mcp gets | enforcement-mcp keeps |
|---------------|----------------------|
| Diagnosis tools | Management tools (set_boolean, load_module) |
| Remediation playbooks | CVE containment pipeline |
| Risk scoring (advisory) | Risk gating (blocks critical changes) |
| SPIFFE/WID identity | Audit trail |
| Read-only output | dry_run + mutation execution |

**Key point:** Clean separation. linux-mcp stays read-only. enforcement-mcp
handles the mutations with full safety stack.

---

## Demo Setup Checklist

### Before the demo

- [ ] Target host SSH accessible (test: `ssh root@host hostname`)
- [ ] SELinux enforcing: `getenforce` → `Enforcing`
- [ ] httpd installed + UserDir configured (for Act 1-5)
- [ ] `/home/testuser/public_html/index.html` exists
- [ ] `httpd_enable_homedirs` boolean OFF: `setsebool httpd_enable_homedirs off`
- [ ] fapolicyd active (for Act 6): `systemctl start fapolicyd`
- [ ] Test binary at `/opt/myapp/bin/worker` (for fapolicyd demo)
- [ ] MCP client configured: `enforcement-mcp check <host>` passes
- [ ] Network access to Red Hat CVE API (for CVE acts)

### Reset between demos

```bash
ssh root@<host> "
  setsebool httpd_enable_homedirs off
  semodule -r fix_httpd_t_read 2>/dev/null
  fapolicyd-cli --file delete /opt/myapp/bin/worker 2>/dev/null
  fapolicyd-cli --update
"
```

### Talking points

- **"Why not just use audit2allow?"** — audit2allow generates policy from
  denials but doesn't explain why, doesn't assess risk, doesn't generate
  Ansible playbooks, doesn't rank alternatives. enforcement-mcp does all four.

- **"What about Ansible Lightspeed?"** — Lightspeed generates generic Ansible.
  enforcement-mcp generates policy-specific playbooks informed by the actual
  SELinux policy on the target host, with risk scoring calibrated to
  enforcement subsystem semantics.

- **"Is this safe to give to an AI agent?"** — Three safety layers:
  1. Diagnosis + remediation are read-only (Tier 1+2)
  2. Management tools default to dry_run=true (Tier 3)
  3. Critical-risk changes (76-100) are hard-blocked

- **"How does this work with WID?"** — SPIFFE workload identity answers
  "which agent is calling?" not "which user started the agent?" This matters
  for multi-agent deployments where agents from different trust domains
  need different access levels.

---

## Arcade Updates Needed

The existing HTML arcade (`docs/enforcement-mcp-arcade.html`) has 9 slides
covering Acts 1-3, 6-9 from Track 1. To update:

1. Add Act 4 (remediation playbook) after the risk assessment slide
2. Add Act 5 (apply fix) — short, shows dry_run→applied transition
3. Update architecture slide with three-tier diagram
4. Update slide count from 9 to 11
5. Update tool count from 29 to 30

Use `demo-recorder build-presentation` with updated manifest if recording
new terminal demos for the new acts.
