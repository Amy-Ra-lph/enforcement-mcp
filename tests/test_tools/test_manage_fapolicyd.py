"""Tests for fapolicyd management tools."""

from unittest.mock import AsyncMock

import pytest

from enforcement_mcp.tools.manage_fapolicyd import (
    fapolicyd_trust_add,
    fapolicyd_trust_remove,
)
from tests.conftest import make_result


class TestFapolicydTrustAdd:
    @pytest.mark.asyncio
    async def test_not_installed(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("", exit_code=1))
        result = await fapolicyd_trust_add(mock_ssh, path="/opt/bin/app")
        assert result["error"] == "fapolicyd_not_installed"

    @pytest.mark.asyncio
    async def test_file_not_found(self, mock_ssh):
        async def mock_execute(cmd):
            if "rpm -q" in cmd:
                return make_result("fapolicyd-1.3.4-1.el9.x86_64")
            if "test -f" in cmd:
                return make_result("")
            return make_result("")

        mock_ssh.execute = mock_execute
        result = await fapolicyd_trust_add(mock_ssh, path="/opt/bin/missing")
        assert result["status"] == "file_not_found"

    @pytest.mark.asyncio
    async def test_dry_run_preview(self, mock_ssh):
        async def mock_execute(cmd):
            if "rpm -q" in cmd:
                return make_result("fapolicyd-1.3.4-1.el9.x86_64")
            if "test -f" in cmd:
                return make_result("exists")
            if "test -u" in cmd:
                return make_result("")
            return make_result("")

        mock_ssh.execute = mock_execute
        result = await fapolicyd_trust_add(
            mock_ssh, path="/opt/bin/app", reason="internal build", dry_run=True
        )
        assert result["status"] == "preview"
        assert result["is_setuid"] is False
        assert "risk_assessment" in result

    @pytest.mark.asyncio
    async def test_setuid_detected(self, mock_ssh):
        async def mock_execute(cmd):
            if "rpm -q" in cmd:
                return make_result("fapolicyd-1.3.4-1.el9.x86_64")
            if "test -f" in cmd:
                return make_result("exists")
            if "test -u" in cmd:
                return make_result("setuid")
            return make_result("")

        mock_ssh.execute = mock_execute
        result = await fapolicyd_trust_add(mock_ssh, path="/opt/bin/app", dry_run=True)
        assert result["is_setuid"] is True
        assert result["risk_assessment"]["risk_score"] > 0

    @pytest.mark.asyncio
    async def test_apply_success(self, mock_ssh):
        async def mock_execute(cmd):
            if "rpm -q" in cmd:
                return make_result("fapolicyd-1.3.4-1.el9.x86_64")
            if "test -f" in cmd:
                return make_result("exists")
            if "test -u" in cmd:
                return make_result("")
            if "--file add" in cmd:
                return make_result("")
            if "--update" in cmd:
                return make_result("")
            if "--dump-db" in cmd:
                return make_result("rpmdb /opt/bin/app 12345 abc123")
            return make_result("")

        mock_ssh.execute = mock_execute
        result = await fapolicyd_trust_add(mock_ssh, path="/opt/bin/app", dry_run=False)
        assert result["status"] == "applied"
        assert result["verified_trusted"] is True


class TestFapolicydTrustRemove:
    @pytest.mark.asyncio
    async def test_not_in_trust(self, mock_ssh):
        async def mock_execute(cmd):
            if "rpm -q" in cmd:
                return make_result("fapolicyd-1.3.4-1.el9.x86_64")
            if "--dump-db" in cmd:
                return make_result("")
            return make_result("")

        mock_ssh.execute = mock_execute
        result = await fapolicyd_trust_remove(mock_ssh, path="/opt/bin/missing")
        assert result["status"] == "not_in_trust"

    @pytest.mark.asyncio
    async def test_dry_run_preview(self, mock_ssh):
        async def mock_execute(cmd):
            if "rpm -q" in cmd:
                return make_result("fapolicyd-1.3.4-1.el9.x86_64")
            if "--dump-db" in cmd:
                return make_result("rpmdb /opt/bin/app 12345 abc123")
            return make_result("")

        mock_ssh.execute = mock_execute
        result = await fapolicyd_trust_remove(mock_ssh, path="/opt/bin/app", dry_run=True)
        assert result["status"] == "preview"
        assert "warning" in result

    @pytest.mark.asyncio
    async def test_apply_success(self, mock_ssh):
        call_count = 0

        async def mock_execute(cmd):
            nonlocal call_count
            call_count += 1
            if "rpm -q" in cmd:
                return make_result("fapolicyd-1.3.4-1.el9.x86_64")
            if "--dump-db" in cmd and call_count <= 2:
                return make_result("rpmdb /opt/bin/app 12345 abc123")
            if "--file delete" in cmd:
                return make_result("")
            if "--update" in cmd:
                return make_result("")
            if "--dump-db" in cmd:
                return make_result("")
            return make_result("")

        mock_ssh.execute = mock_execute
        result = await fapolicyd_trust_remove(mock_ssh, path="/opt/bin/app", dry_run=False)
        assert result["status"] == "removed"
        assert result["verified_removed"] is True
