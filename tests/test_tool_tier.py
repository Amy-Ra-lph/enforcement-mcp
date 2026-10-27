"""Tests for the tool-tier system."""

import os
import subprocess
import sys


def _count_tools(tier_value: str | None, identity_mode: str = "none") -> dict:
    """Spawn a subprocess to test tier registration (modules cache tier at import)."""
    env = {**os.environ, "ENFORCEMENT_MCP_HOST": "localhost"}
    if tier_value is not None:
        env["ENFORCEMENT_MCP_TOOL_TIER"] = tier_value
    else:
        env.pop("ENFORCEMENT_MCP_TOOL_TIER", None)
    env["ENFORCEMENT_MCP_IDENTITY_MODE"] = identity_mode

    code = """
import asyncio, json
from enforcement_mcp.server import mcp, _tool_tier
tools = asyncio.run(mcp.list_tools())
names = sorted(t.name for t in tools)
manage = [n for n in names if n.startswith("manage.")]
diag = [n for n in names if n.startswith("diagnosis.")]
print(json.dumps({"tier": _tool_tier.name, "total": len(names),
                   "diagnosis": len(diag), "manage": len(manage),
                   "manage_names": manage}))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, env=env, timeout=30,
    )
    assert result.returncode == 0, f"subprocess failed: {result.stderr}"
    import json
    return json.loads(result.stdout.strip())


def test_diagnosis_tier():
    info = _count_tools("diagnosis")
    assert info["tier"] == "DIAGNOSIS"
    assert info["total"] == 18
    assert info["manage"] == 0


def test_remediation_tier():
    info = _count_tools("remediation")
    assert info["tier"] == "REMEDIATION"
    assert info["total"] == 22
    assert info["manage"] == 4
    assert "manage.assess_risk" in info["manage_names"]
    assert "manage.cve_contain" in info["manage_names"]
    assert "manage.set_boolean" not in info["manage_names"]


def test_management_tier():
    info = _count_tools("management")
    assert info["tier"] == "MANAGEMENT"
    assert info["total"] == 30
    assert info["manage"] == 12


def test_auto_detect_no_auth_defaults_diagnosis():
    info = _count_tools(None, identity_mode="none")
    assert info["tier"] == "DIAGNOSIS"
    assert info["manage"] == 0


def test_auto_detect_oauth_defaults_management():
    info = _count_tools(None, identity_mode="oauth")
    assert info["tier"] == "MANAGEMENT"
    assert info["manage"] == 12


def test_explicit_tier_overrides_auto_detect():
    info = _count_tools("diagnosis", identity_mode="oauth")
    assert info["tier"] == "DIAGNOSIS"
    assert info["manage"] == 0
