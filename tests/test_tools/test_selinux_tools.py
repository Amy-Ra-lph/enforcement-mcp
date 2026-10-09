"""Tests for SELinux diagnosis tools."""

from unittest.mock import AsyncMock

import pytest

from enforcement_mcp.tools.selinux import avc_denials, boolean_list, file_context, policy_query
from tests.conftest import make_result


class TestAvcDenials:
    @pytest.mark.asyncio
    async def test_returns_structured_denials(self, mock_ssh):
        raw_avc = (
            "----\n"
            "time->Thu Oct  9 14:32:01 2026\n"
            "type=AVC msg=audit(1760012521.123:456): avc:  denied  { read } "
            'for  pid=4821 comm="httpd" name="index.html" '
            "scontext=system_u:system_r:httpd_t:s0 "
            "tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0\n"
        )
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result(raw_avc),
            ]
        )

        result = await avc_denials(mock_ssh, since="1h")
        assert result["total"] == 1
        assert result["denials"][0]["source_type"] == "httpd_t"

    @pytest.mark.asyncio
    async def test_selinux_disabled_returns_error(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Disabled"))

        result = await avc_denials(mock_ssh)
        assert result["error"] == "selinux_disabled"

    @pytest.mark.asyncio
    async def test_no_denials(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("<no matches>"),
            ]
        )

        result = await avc_denials(mock_ssh)
        assert result["denials"] == []
        assert result["total"] == 0


class TestBooleanList:
    @pytest.mark.asyncio
    async def test_returns_booleans(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("httpd_enable_homedirs --> off\nhttpd_can_network_connect --> off\n"),
            ]
        )

        result = await boolean_list(mock_ssh)
        assert len(result["booleans"]) == 2

    @pytest.mark.asyncio
    async def test_filter(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result(
                    "httpd_enable_homedirs --> off\n"
                    "httpd_can_network_connect --> off\n"
                    "samba_enable_home_dirs --> off\n"
                ),
            ]
        )

        result = await boolean_list(mock_ssh, filter_str="httpd")
        assert len(result["booleans"]) == 2


class TestFileContext:
    @pytest.mark.asyncio
    async def test_mismatch_detected(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("/home/jsmith/public_html\tsystem_u:object_r:httpd_sys_content_t:s0\n"),
                make_result("system_u:object_r:user_home_dir_t:s0 /home/jsmith/public_html\n"),
            ]
        )

        result = await file_context(mock_ssh, path="/home/jsmith/public_html")
        assert result["mismatch"] is True
        assert result["expected_type"] == "httpd_sys_content_t"
        assert result["actual_type"] == "user_home_dir_t"

    @pytest.mark.asyncio
    async def test_match(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("/var/www/html\tsystem_u:object_r:httpd_sys_content_t:s0\n"),
                make_result("system_u:object_r:httpd_sys_content_t:s0 /var/www/html\n"),
            ]
        )

        result = await file_context(mock_ssh, path="/var/www/html")
        assert result["mismatch"] is False


class TestPolicyQuery:
    @pytest.mark.asyncio
    async def test_returns_rules(self, mock_ssh):
        raw = "allow httpd_t httpd_sys_content_t : file { read open getattr } ;\n"
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result(raw),
            ]
        )

        result = await policy_query(mock_ssh, source_type="httpd_t", tclass="file")
        assert len(result["rules"]) == 1
        assert result["rules"][0]["target"] == "httpd_sys_content_t"
