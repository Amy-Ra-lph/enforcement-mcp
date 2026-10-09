"""Tests for CVE containment management tools."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from enforcement_mcp.tools.containment import containment_expire, cve_contain
from tests.conftest import make_result


class TestCveContain:
    @pytest.mark.asyncio
    async def test_invalid_cve_id(self, mock_ssh):
        result = await cve_contain(mock_ssh, cve_id="bad-id")
        assert result["error"] == "invalid_cve_id"

    @pytest.mark.asyncio
    async def test_selinux_disabled(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Disabled"))
        result = await cve_contain(mock_ssh, cve_id="CVE-2024-6387")
        assert result["error"] == "selinux_disabled"

    @pytest.mark.asyncio
    @patch("enforcement_mcp.tools.containment.fetch_cve")
    async def test_generates_containment_options(self, mock_fetch, mock_ssh):
        mock_fetch.return_value = {
            "name": "CVE-2024-6387",
            "threat_severity": "Important",
            "cvss3": {"cvss3_base_score": "8.1"},
            "details": ["A race condition in sshd."],
            "package_state": [{"package_name": "openssh"}],
            "affected_release": [],
            "cwe": "CWE-364",
        }

        async def mock_execute(cmd):
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "sesearch" in cmd:
                return make_result("allow sshd_t tmp_t : file { read write } ;")
            return make_result("")

        mock_ssh.execute = mock_execute

        result = await cve_contain(mock_ssh, cve_id="CVE-2024-6387", strategy="all")
        assert result["containment_needed"] is True
        assert len(result["options"]) > 0
        assert result["gaps_found"] > 0

        for opt in result["options"]:
            assert "cil_content" in opt
            assert "module_name" in opt
            assert "risk_assessment" in opt
            assert opt["module_name"].startswith("emcp_")

    @pytest.mark.asyncio
    @patch("enforcement_mcp.tools.containment.fetch_cve")
    async def test_no_containment_needed(self, mock_fetch, mock_ssh):
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
                return make_result("")
            return make_result("")

        mock_ssh.execute = mock_execute

        result = await cve_contain(mock_ssh, cve_id="CVE-2024-0001", strategy="minimal")
        assert result["containment_needed"] is False

    @pytest.mark.asyncio
    @patch("enforcement_mcp.tools.containment.fetch_cve")
    async def test_minimal_strategy(self, mock_fetch, mock_ssh):
        mock_fetch.return_value = {
            "name": "CVE-2024-6387",
            "threat_severity": "Important",
            "details": ["sshd race condition."],
            "package_state": [{"package_name": "openssh"}],
            "affected_release": [],
            "cwe": "CWE-364",
        }

        async def mock_execute(cmd):
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "sesearch" in cmd:
                return make_result("allow sshd_t tmp_t : file { write } ;")
            return make_result("")

        mock_ssh.execute = mock_execute

        result = await cve_contain(mock_ssh, cve_id="CVE-2024-6387", strategy="minimal")
        if result.get("containment_needed"):
            assert all(o["strategy"] == "minimal" for o in result["options"])


class TestContainmentExpire:
    @pytest.mark.asyncio
    async def test_invalid_cve_id(self, mock_ssh):
        result = await containment_expire(mock_ssh, cve_id="bad")
        assert result["error"] == "invalid_cve_id"

    @pytest.mark.asyncio
    async def test_no_state_file(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("", exit_code=1))
        result = await containment_expire(mock_ssh, cve_id="CVE-2024-6387")
        assert result["error"] == "no_containments"

    @pytest.mark.asyncio
    async def test_cve_not_found_in_state(self, mock_ssh):
        state = json.dumps([{"cve_id": "CVE-2024-0001", "module_name": "emcp_test"}])
        mock_ssh.execute = AsyncMock(return_value=make_result(state))
        result = await containment_expire(mock_ssh, cve_id="CVE-2024-9999")
        assert result["error"] == "not_found"

    @pytest.mark.asyncio
    async def test_module_already_removed(self, mock_ssh):
        state = json.dumps(
            [
                {"cve_id": "CVE-2024-6387", "module_name": "emcp_cve_2024_6387_minimal"},
            ]
        )

        async def mock_execute(cmd):
            if "cat" in cmd:
                return make_result(state)
            if "semodule" in cmd:
                return make_result("")
            return make_result("", exit_code=1)

        mock_ssh.execute = mock_execute

        result = await containment_expire(mock_ssh, cve_id="CVE-2024-6387")
        assert result["status"] == "already_removed"

    @pytest.mark.asyncio
    async def test_patched_safe_to_remove(self, mock_ssh):
        state = json.dumps(
            [
                {
                    "cve_id": "CVE-2024-6387",
                    "module_name": "emcp_cve_2024_6387_minimal",
                    "fixed_in": ["openssh-9.6p1-1.el9"],
                },
            ]
        )

        async def mock_execute(cmd):
            if "cat" in cmd:
                return make_result(state)
            if "semodule" in cmd:
                return make_result("emcp_cve_2024_6387_minimal")
            if "rpm" in cmd:
                return make_result("openssh-9.6p1-1.el9.x86_64")
            return make_result("", exit_code=1)

        mock_ssh.execute = mock_execute

        result = await containment_expire(mock_ssh, cve_id="CVE-2024-6387")
        assert result["patched"] is True
        assert result["safe_to_remove"] is True
        assert "semodule -r" in result["remove_command"]

    @pytest.mark.asyncio
    async def test_not_patched_unsafe_to_remove(self, mock_ssh):
        state = json.dumps(
            [
                {
                    "cve_id": "CVE-2024-6387",
                    "module_name": "emcp_cve_2024_6387_minimal",
                    "fixed_in": ["openssh-9.6p1-1.el9"],
                },
            ]
        )

        async def mock_execute(cmd):
            if "cat" in cmd:
                return make_result(state)
            if "semodule" in cmd:
                return make_result("emcp_cve_2024_6387_minimal")
            if "rpm" in cmd:
                return make_result("", exit_code=1)
            return make_result("", exit_code=1)

        mock_ssh.execute = mock_execute

        result = await containment_expire(mock_ssh, cve_id="CVE-2024-6387")
        assert result["patched"] is False
        assert result["safe_to_remove"] is False
