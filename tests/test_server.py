"""Tests for MCP server setup."""

import pytest

from enforcement_mcp.server import mcp


class TestServerSetup:
    def test_server_name(self):
        assert mcp.name == "enforcement-mcp"

    @pytest.mark.asyncio
    async def test_tool_count(self):
        tools = await mcp.list_tools()
        assert len(tools) == 29

    @pytest.mark.asyncio
    async def test_diagnosis_tools_registered(self):
        tools = await mcp.list_tools()
        tool_names = [t.name for t in tools]
        expected = [
            "diagnosis.troubleshoot",
            "diagnosis.host_posture",
            "diagnosis.avc_denials",
            "diagnosis.policy_query",
            "diagnosis.boolean_list",
            "diagnosis.file_context",
            "diagnosis.denial_explain",
            "diagnosis.fapolicyd_status",
            "diagnosis.fapolicyd_denials",
            "diagnosis.fapolicyd_trust_check",
            "diagnosis.fapolicyd_rules",
            "diagnosis.mls_user_mappings",
            "diagnosis.mls_file_level",
            "diagnosis.mls_categories",
            "diagnosis.cve_exposure",
            "diagnosis.active_containments",
            "diagnosis.parse_denials",
        ]
        for name in expected:
            assert name in tool_names, f"Missing tool: {name}"

    @pytest.mark.asyncio
    async def test_management_tools_registered(self):
        tools = await mcp.list_tools()
        tool_names = [t.name for t in tools]
        expected_manage = [
            "manage.assess_risk",
            "manage.cve_contain",
            "manage.containment_expire",
            "manage.set_boolean",
            "manage.generate_module",
            "manage.load_module",
            "manage.remove_module",
            "manage.set_file_context",
            "manage.fapolicyd_trust_add",
            "manage.fapolicyd_trust_remove",
            "manage.mls_assign_category",
            "manage.mls_set_user_range",
        ]
        for name in expected_manage:
            assert name in tool_names, f"Missing tool: {name}"
