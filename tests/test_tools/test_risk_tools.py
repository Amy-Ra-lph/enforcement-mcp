"""Tests for risk assessment tool."""

from unittest.mock import AsyncMock

import pytest

from enforcement_mcp.tools.risk import assess_risk
from tests.conftest import make_result


class TestAssessRisk:
    @pytest.mark.asyncio
    async def test_unknown_change_type(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Enforcing"))
        result = await assess_risk(mock_ssh, change_type="unknown_type")
        assert result["error"] == "unknown_change_type"

    @pytest.mark.asyncio
    async def test_selinux_disabled_for_boolean(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Disabled"))
        result = await assess_risk(mock_ssh, change_type="boolean", name="test_bool")
        assert result["error"] == "selinux_disabled"

    @pytest.mark.asyncio
    async def test_boolean_assessment(self, mock_ssh):
        async def mock_execute(cmd):
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "sesearch" in cmd:
                return make_result(
                    "allow httpd_t user_home_t : file { read getattr } ; [ httpd_enable_homedirs ]:True\n"
                )
            return make_result("")

        mock_ssh.execute = mock_execute

        result = await assess_risk(
            mock_ssh, change_type="boolean", name="httpd_enable_homedirs", value=True
        )
        assert "risk_score" in result
        assert "risk_level" in result
        assert "blast_radius" in result
        assert "recommendation" in result

    @pytest.mark.asyncio
    async def test_boolean_missing_name(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Enforcing"))
        result = await assess_risk(mock_ssh, change_type="boolean")
        assert result["error"] == "missing_param"

    @pytest.mark.asyncio
    async def test_module_assessment(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Enforcing"))
        cil = "(allow httpd_t tmp_t (file (read write)))"
        result = await assess_risk(
            mock_ssh, change_type="module", name="test_mod", cil=cil
        )
        assert "risk_score" in result
        assert "risk_level" in result

    @pytest.mark.asyncio
    async def test_fapolicyd_trust_assessment(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Enforcing"))
        result = await assess_risk(
            mock_ssh, change_type="fapolicyd_trust", path="/opt/myapp/bin/worker"
        )
        assert "risk_score" in result
        assert result["risk_level"] == "low"

    @pytest.mark.asyncio
    async def test_fapolicyd_trust_tmp_high_risk(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Enforcing"))
        result = await assess_risk(
            mock_ssh, change_type="fapolicyd_trust", path="/tmp/malware"
        )
        assert result["risk_score"] >= 25

    @pytest.mark.asyncio
    async def test_fapolicyd_trust_missing_path(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Enforcing"))
        result = await assess_risk(mock_ssh, change_type="fapolicyd_trust")
        assert result["error"] == "missing_param"
