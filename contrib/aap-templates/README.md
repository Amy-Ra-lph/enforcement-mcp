# AAP Job Templates for enforcement-mcp Remediation

Ansible Automation Platform job templates that pair with enforcement-mcp's
diagnosis tools. An AI agent uses enforcement-mcp to diagnose, then launches
these templates through the [AAP MCP server](https://github.com/ansible/aap-mcp-server)
to remediate.

## Architecture: dual-path remediation

```
AI Agent
├── enforcement-mcp (diagnosis)
│   ├── troubleshoot → root cause
│   ├── denial_explain → fix options
│   └── generate_playbook → fallback YAML
│
├── aap-mcp-server (primary remediation)
│   ├── job_templates_list → find matching template
│   ├── job_templates_launch_create → run with extra_vars
│   └── jobs_read → poll status
│
└── Fallback: generate_playbook → user runs ansible-playbook
```

**Primary path:** Agent connects to both MCP servers. Diagnosis findings
map to AAP job template extra_vars. Agent launches the template, polls
until complete.

**Fallback path:** No AAP available. Agent uses `generate_playbook` to
emit ready-to-run YAML using `fedora.linux_system_roles`. User runs it
manually.

## Templates included

| Template | Playbook | Use case |
|----------|----------|----------|
| `selinux-boolean-remediation` | `selinux_boolean.yml` | Toggle SELinux boolean |
| `selinux-relabel-remediation` | `selinux_relabel.yml` | Fix file context mismatch |
| `selinux-module-remediation` | `selinux_module.yml` | Load custom CIL policy module |
| `fapolicyd-trust-remediation` | `fapolicyd_trust.yml` | Add binary to fapolicyd trust |
| `aide-baseline-remediation` | `aide_baseline.yml` | Update AIDE baseline after approved changes |

## Setup in AAP

1. Create a project pointing to this repo (or sync these playbooks)
2. Import each job template from `job-templates.yml`
3. Assign an inventory containing your RHEL hosts
4. Assign a machine credential with SSH access

```bash
# Import all templates via awx CLI
awx-cli import < job-templates.yml
```

Or create manually in the AAP UI using the parameters in `job-templates.yml`.

## Diagnosis → extra_vars mapping

Each template accepts extra_vars that map directly to enforcement-mcp
diagnosis output:

| Diagnosis field | extra_var | Example |
|----------------|-----------|---------|
| `boolean` | `selinux_boolean` | `httpd_enable_homedirs` |
| `source_type` | `source_type` | `httpd_t` |
| `target_type` | `target_type` | `user_home_t` |
| `path` | `target_path` | `/home/jsmith/public_html` |
| `tclass` | `target_class` | `file` |
| `permission` | `permission` | `read` |
| `new_context` | `new_context` | `httpd_sys_content_t` |
| `cil_content` | `cil_module_content` | `(allow httpd_t ...)` |
| `binary_path` | `binary_path` | `/opt/app/bin/myapp` |

## Requirements

- Ansible Automation Platform 2.5+
- `fedora.linux_system_roles` collection installed in execution environment
- `community.general` collection (for fapolicyd/AIDE)
- Machine credential with root or sudo access on target hosts
