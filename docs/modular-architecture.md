# enforcement-mcp: Modular Architecture

## Problem

enforcement-mcp's SELinux, fapolicyd, and MLS tools are tightly coupled to this MCP server.
Other MCP servers (linux-mcp, custom deployments) can't consume individual modules without
taking the whole package. Adding new subsystems (AIDE, auditd, etc.) means editing the
monolith.

## Design: Plugin Modules

Each security subsystem becomes a self-contained module that any MCP server can import and
register. enforcement-mcp becomes a thin orchestrator that loads modules.

```
enforcement_mcp/
├── modules/
│   ├── __init__.py          # Module registry + discovery
│   ├── selinux/
│   │   ├── __init__.py      # register_tools(mcp) entry point
│   │   ├── tools.py         # Read-only tools (status, booleans, denials, ...)
│   │   ├── manage.py        # Write tools (set_boolean, load_module, ...)
│   │   ├── parsers.py       # sestatus, getsebool, ausearch parsing
│   │   ├── models.py        # Pydantic models
│   │   └── commands.py      # CommandSpec definitions
│   ├── fapolicyd/
│   │   ├── __init__.py
│   │   ├── tools.py
│   │   ├── manage.py
│   │   ├── parsers.py
│   │   └── models.py
│   ├── mls/
│   │   ├── __init__.py
│   │   ├── tools.py
│   │   ├── manage.py
│   │   ├── parsers.py
│   │   └── models.py
│   └── aide/                # NEW — file integrity monitoring
│       ├── __init__.py
│       ├── tools.py         # aide_check, aide_report, aide_config
│       ├── manage.py        # aide_update_db, aide_init_db
│       ├── parsers.py       # Parse AIDE check output
│       └── models.py        # AIDEChange, AIDEReport, etc.
├── composite/               # Tools that span multiple modules
│   ├── posture.py           # host_posture (SELinux + fapolicyd + MLS + AIDE)
│   ├── troubleshoot.py      # Root-cause chain
│   ├── risk.py              # Risk assessment
│   └── containment.py       # CVE containment
├── tools/
│   └── remediate.py         # Playbook generator (Tier 2 — read-only output)
└── server.py                # Loads modules, registers composite tools
```

## Module Contract

Each module exposes:

```python
# modules/selinux/__init__.py

def register_readonly_tools(mcp_server):
    """Register read-only tools. Safe for linux-mcp upstream."""
    from .tools import (
        get_selinux_status,
        get_selinux_booleans,
        get_selinux_file_context,
        get_selinux_denials,
        get_selinux_policy_query,
    )

def register_management_tools(mcp_server):
    """Register write/management tools. enforcement-mcp only."""
    from .manage import (
        set_boolean,
        generate_module,
        load_module,
        remove_module,
        set_file_context,
    )

def register_all(mcp_server):
    """Register everything."""
    register_readonly_tools(mcp_server)
    register_management_tools(mcp_server)
```

## Consumer Usage

### linux-mcp (read-only)
```python
from enforcement_mcp.modules.selinux import register_readonly_tools
register_readonly_tools(mcp)  # Only safe, read-only tools
```

### enforcement-mcp (everything)
```python
from enforcement_mcp.modules import discover_modules
for module in discover_modules():
    module.register_all(mcp)
```

### Custom MCP (cherry-pick)
```python
from enforcement_mcp.modules.selinux import register_readonly_tools
from enforcement_mcp.modules.aide import register_all
register_readonly_tools(mcp)  # SELinux read-only
register_all(mcp)             # AIDE everything
```

## AIDE Module Design

Based on [linux-system-roles/aide](https://github.com/linux-system-roles/aide) and
the AIDE CLI:

### Read-Only Tools (→ linux-mcp candidate)

| Tool | Command | Description |
|------|---------|-------------|
| `aide_check` | `aide --check` | Run integrity check, return changed/added/removed files |
| `aide_report` | `aide --check` + parse | Structured report: file path, change type, attributes |
| `aide_config` | Read `/etc/aide.conf` | Current AIDE configuration and watched paths |

### Management Tools (→ enforcement-mcp only)

| Tool | Command | Description |
|------|---------|-------------|
| `aide_init_db` | `aide --init` | Initialize the AIDE database |
| `aide_update_db` | `aide --update` | Update database after known-good changes |

### Models

```python
class AIDEChange(BaseModel):
    path: str
    change_type: Literal["added", "removed", "changed"]
    attributes: dict  # permissions, size, mtime, checksum changes

class AIDEReport(BaseModel):
    changes: list[AIDEChange]
    total_files_checked: int
    added: int
    removed: int
    changed: int
    scan_time: str
```

## Three-Tier Architecture

Tools are organized into permission tiers:

| Tier | Scope | Auth Required | Examples |
|------|-------|---------------|----------|
| **Tier 1: Diagnosis** | Read-only system queries | No | `troubleshoot`, `avc_denials`, `host_posture` |
| **Tier 2: Remediation** | Generate fix playbooks (YAML output only) | No | `generate_playbook` |
| **Tier 3: Management** | Mutating policy changes | Yes (if strict) | `set_boolean`, `load_module`, `fapolicyd_trust_add` |

Tier 2 (`tools/remediate.py`) bridges diagnosis and management. It reads system
state to generate ranked Ansible playbooks using `fedora.linux_system_roles`, but
never executes them. Each alternative includes a risk assessment from the scoring
engine. This is safe for upstream contribution (e.g., linux-mcp) since it produces
text output only.

Supported finding types: `denial`, `file_context`, `fapolicyd_block`, `aide_change`.

## Migration Path

1. Current tools stay working — no breaking changes
2. New module structure added alongside existing code
3. Existing tools gradually migrated into modules
4. pyproject.toml extras: `pip install enforcement-mcp[selinux,aide]`
5. linux-mcp can depend on `enforcement-mcp[selinux]` for read-only tools

## Versioning

Each module follows the main package version. Module API stability:
- `register_readonly_tools()` — stable, matches linux-mcp contribution
- `register_management_tools()` — stable within enforcement-mcp
- Internal parsers/models — semver, may change between minor versions
