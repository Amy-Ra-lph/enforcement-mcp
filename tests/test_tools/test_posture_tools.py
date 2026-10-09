"""Tests for composite diagnosis tools."""

from unittest.mock import AsyncMock

import pytest

from enforcement_mcp.tools.posture import host_posture, troubleshoot
from tests.conftest import make_result


class TestHostPosture:
    @pytest.mark.asyncio
    async def test_returns_full_posture(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("SELINUXTYPE=targeted"),
                make_result("<no matches>"),
                make_result(""),
                make_result("httpd_enable_homedirs --> off\n"),
                make_result("", exit_code=0),
                make_result("active"),
                make_result("15"),
                make_result("48231"),
                make_result("<no matches>"),
                make_result(
                    "Login Name           SELinux User         MLS/MCS Range\n"
                    "__default__          unconfined_u         s0-s0:c0.c1023\n"
                ),
            ]
        )

        result = await host_posture(mock_ssh)
        assert "selinux" in result
        assert "fapolicyd" in result
        assert "mls" in result
        assert "posture_score" in result
        assert result["selinux"]["mode"] == "enforcing"
        assert result["fapolicyd"]["active"] is True
        assert result["posture_score"] == 100


class TestTroubleshoot:
    @pytest.mark.asyncio
    async def test_finds_selinux_denial(self, mock_ssh):
        avc_line = (
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
                make_result(avc_line),
                make_result("", exit_code=0),
                make_result("<no matches>"),
                make_result("drwxr-xr-x. root root /home/jsmith/public_html\n"),
            ]
        )

        result = await troubleshoot(
            mock_ssh,
            symptom="httpd can't serve /home/jsmith/public_html",
            process="httpd",
            path="/home/jsmith/public_html",
        )

        assert result["root_cause"] == "selinux"
        assert len(result["denials_found"]) > 0
        assert result["confidence"] == "high"

    @pytest.mark.asyncio
    async def test_no_enforcement_issue(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("<no matches>"),
                make_result("", exit_code=0),
                make_result("<no matches>"),
                make_result("-rw-r--r--. root root /var/www/html/index.html\n"),
            ]
        )

        result = await troubleshoot(
            mock_ssh,
            symptom="httpd returns 500",
            process="httpd",
            path="/var/www/html/index.html",
        )

        assert result["root_cause"] == "not_enforcement"
        assert "suggestions" in result
