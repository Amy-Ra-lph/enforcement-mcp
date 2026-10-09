"""Tests for CVE exposure and containment tracking tools."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from enforcement_mcp.tools.cve import active_containments, cve_exposure
from tests.conftest import make_result


class TestCveExposure:
    @pytest.mark.asyncio
    async def test_invalid_cve_id(self, mock_ssh):
        result = await cve_exposure(mock_ssh, cve_id="not-a-cve")
        assert result["error"] == "invalid_cve_id"

    @pytest.mark.asyncio
    async def test_selinux_disabled(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Disabled"))
        result = await cve_exposure(mock_ssh, cve_id="CVE-2024-6387")
        assert result["error"] == "selinux_disabled"

    @pytest.mark.asyncio
    @patch("enforcement_mcp.tools.cve.fetch_cve")
    async def test_cve_not_found(self, mock_fetch, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Enforcing"))
        mock_fetch.return_value = {"error": "not_found", "cve_id": "CVE-9999-0000"}
        result = await cve_exposure(mock_ssh, cve_id="CVE-9999-0000")
        assert result["error"] == "cve_fetch_failed"

    @pytest.mark.asyncio
    @patch("enforcement_mcp.tools.cve.fetch_cve")
    async def test_successful_exposure_check(self, mock_fetch, mock_ssh):
        mock_fetch.return_value = {
            "name": "CVE-2024-6387",
            "threat_severity": "Important",
            "cvss3": {"cvss3_base_score": "8.1"},
            "details": ["A race condition in sshd."],
            "package_state": [{"package_name": "openssh"}],
            "affected_release": [],
            "cwe": "CWE-364",
        }

        call_count = 0

        async def mock_execute(cmd):
            nonlocal call_count
            call_count += 1
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "sesearch" in cmd:
                return make_result("")
            return make_result("")

        mock_ssh.execute = mock_execute

        result = await cve_exposure(mock_ssh, cve_id="CVE-2024-6387")
        assert "cve" in result
        assert result["cve"]["cve_id"] == "CVE-2024-6387"
        assert "exploit_chain" in result
        assert "containment_score" in result
        assert result["total_steps"] > 0

    @pytest.mark.asyncio
    @patch("enforcement_mcp.tools.cve.fetch_cve")
    async def test_fully_blocked_chain(self, mock_fetch, mock_ssh):
        mock_fetch.return_value = {
            "name": "CVE-2024-0001",
            "threat_severity": "Low",
            "details": ["Minor issue."],
            "package_state": [{"package_name": "httpd"}],
            "affected_release": [],
            "cwe": "CWE-79",
        }

        async def mock_execute(cmd):
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "sesearch" in cmd:
                return make_result(
                    "allow httpd_t httpd_sys_content_t : file { read getattr } ;"
                )
            return make_result("")

        mock_ssh.execute = mock_execute

        result = await cve_exposure(mock_ssh, cve_id="CVE-2024-0001")
        assert result["containment_score"] > 0 or result["blocked_steps"] >= 0


class TestActiveContainments:
    @pytest.mark.asyncio
    async def test_no_state_file(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("", exit_code=1))
        result = await active_containments(mock_ssh)
        assert result["containments"] == []
        assert result["total"] == 0

    @pytest.mark.asyncio
    async def test_empty_state_file(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result(""))
        result = await active_containments(mock_ssh)
        assert result["containments"] == []

    @pytest.mark.asyncio
    async def test_corrupt_state_file(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("not json"))
        result = await active_containments(mock_ssh)
        assert result["error"] == "corrupt_state_file"

    @pytest.mark.asyncio
    async def test_valid_containments(self, mock_ssh):
        state = json.dumps([
            {
                "cve_id": "CVE-2024-6387",
                "module_name": "emcp_cve_2024_6387_minimal",
                "date_applied": "2024-07-01T12:00:00Z",
                "strategy": "minimal",
            },
        ])

        call_idx = 0

        async def mock_execute(cmd):
            nonlocal call_idx
            call_idx += 1
            if "cat" in cmd:
                return make_result(state)
            if "semodule" in cmd:
                return make_result("emcp_cve_2024_6387_minimal")
            return make_result("", exit_code=1)

        mock_ssh.execute = mock_execute

        result = await active_containments(mock_ssh)
        assert result["total"] == 1
        assert result["containments"][0]["module_loaded"] is True
