# AWX Demo for enforcement-mcp

Deploys AWX + aap-mcp-server on a Beaker host for the agentic security PoC.
Enables the dual-path remediation architecture: enforcement-mcp diagnoses,
aap-mcp-server launches AWX job templates to remediate.

## Architecture

```
Claude Code / LLM
    ├── enforcement-mcp (diagnosis)
    │     └── SELinux/fapolicyd/AIDE tools → target host
    └── aap-mcp-server (remediation)
          └── AWX API → job template launch → target host
```

## Quick Start

```bash
./setup.sh sweetpig-1.khw.eng.rdu2.dc.redhat.com
```

This runs two Ansible playbooks:
1. `deploy-awx.yml` — installs k3s, AWX operator, AWX instance, aap-mcp-server
2. `configure-templates.yml` — creates job templates from `../aap-templates/`

## Manual Setup

```bash
# Deploy
ansible-playbook deploy-awx.yml -i <host>, -e awx_admin_password=<pw> -u root

# Get token
TOKEN=$(curl -sf -X POST http://<host>:30080/api/v2/tokens/ \
    -u admin:<pw> | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Configure templates
ansible-playbook configure-templates.yml -i <host>, -e awx_token=$TOKEN -u root
```

## AWX Compatibility Patches

aap-mcp-server is designed for AAP 2.7 (with Gateway). Two patches for standalone AWX:

1. **Auth endpoint**: `/api/gateway/v1/me/` → `/api/v2/me/` in `dist/index.js`
2. **URL prefix**: Disable `/api/controller/v2` rewrite in `dist/openapi-loader.js`

Both patches are applied automatically by `deploy-awx.yml`.

## Files

| File | Purpose |
|------|---------|
| `deploy-awx.yml` | Full deployment playbook (k3s + AWX + aap-mcp-server) |
| `configure-templates.yml` | Job template creation (re-runnable) |
| `setup.sh` | One-command deployment wrapper |
| `aap-mcp.yaml` | aap-mcp-server configuration template |

## Requirements

- RHEL 10.x target host with 8GB+ RAM
- Root SSH access
- Internet access (github.com, quay.io, registry.k8s.io)

## Current Deployment

- **Host**: sweetpig-1.khw.eng.rdu2.dc.redhat.com
- **AWX**: http://sweetpig-1.khw.eng.rdu2.dc.redhat.com:30080 (admin/Agentic2026!)
- **MCP**: http://sweetpig-1.khw.eng.rdu2.dc.redhat.com:3000/mcp
- **AWX version**: 24.6.1
- **k3s version**: v1.36.5+k3s1
