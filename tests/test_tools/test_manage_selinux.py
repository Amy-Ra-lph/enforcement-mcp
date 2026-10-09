"""Tests for SELinux management tools."""

from unittest.mock import AsyncMock

import pytest

from enforcement_mcp.tools.manage_selinux import (
    generate_module,
    load_module,
    remove_module,
    set_boolean,
    set_file_context,
)
from tests.conftest import make_result


class TestSetBoolean:
    @pytest.mark.asyncio
    async def test_selinux_disabled(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Disabled"))
        result = await set_boolean(mock_ssh, name="test", value=True)
        assert result["error"] == "selinux_disabled"

    @pytest.mark.asyncio
    async def test_dry_run_preview(self, mock_ssh):
        async def mock_execute(cmd):
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "sesearch" in cmd:
                return make_result(
                    "allow httpd_t user_home_t : file { read } ; "
                    "[ httpd_enable_homedirs ]:True\n"
                )
            if "getsebool" in cmd:
                return make_result("httpd_enable_homedirs --> off")
            return make_result("")

        mock_ssh.execute = mock_execute

        result = await set_boolean(
            mock_ssh, name="httpd_enable_homedirs", value=True, dry_run=True
        )
        assert result["status"] == "preview"
        assert result["current_value"] == "off"
        assert result["new_value"] == "on"
        assert "risk_assessment" in result
        assert "setsebool" in result["command"]

    @pytest.mark.asyncio
    async def test_apply_success(self, mock_ssh):
        async def mock_execute(cmd):
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "sesearch" in cmd:
                return make_result("")
            if "setsebool" in cmd:
                return make_result("")
            if "getsebool" in cmd:
                return make_result("httpd_enable_homedirs --> on")
            return make_result("")

        mock_ssh.execute = mock_execute

        result = await set_boolean(
            mock_ssh, name="httpd_enable_homedirs", value=True, dry_run=False
        )
        assert result["status"] == "applied"
        assert result["verified_value"] == "on"


class TestGenerateModule:
    @pytest.mark.asyncio
    async def test_no_denials(self, mock_ssh):
        async def mock_execute(cmd):
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "ausearch" in cmd:
                return make_result("<no matches>")
            return make_result("")

        mock_ssh.execute = mock_execute

        result = await generate_module(mock_ssh, name="test_mod", from_denials="1h")
        assert result["status"] == "no_denials"

    @pytest.mark.asyncio
    async def test_generates_cil(self, mock_ssh):
        avc_line = (
            "----\n"
            "time->Thu Oct  9 14:32:01 2026\n"
            'type=AVC msg=audit(1760012521.123:456): avc:  denied  { read } '
            'for  pid=4821 comm="httpd" name="index.html" '
            'scontext=system_u:system_r:httpd_t:s0 '
            'tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0\n'
        )

        async def mock_execute(cmd):
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "ausearch" in cmd:
                return make_result(avc_line)
            if "sesearch" in cmd:
                return make_result("")
            return make_result("")

        mock_ssh.execute = mock_execute

        result = await generate_module(
            mock_ssh, name="httpd_fix", from_denials="1h", source_type="httpd_t"
        )
        assert result["status"] == "generated"
        assert "(allow httpd_t" in result["cil_content"]
        assert "risk_assessment" in result


class TestLoadModule:
    @pytest.mark.asyncio
    async def test_dry_run(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Enforcing"))
        cil = "(allow httpd_t user_home_t (file (read)))"
        result = await load_module(mock_ssh, name="test", cil=cil, dry_run=True)
        assert result["status"] == "preview"

    @pytest.mark.asyncio
    async def test_apply_success(self, mock_ssh):
        async def mock_execute(cmd):
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "cat >" in cmd:
                return make_result("")
            if "semodule -i" in cmd:
                return make_result("")
            if "semodule -l" in cmd:
                return make_result("test")
            if "rm -f" in cmd:
                return make_result("")
            return make_result("")

        mock_ssh.execute = mock_execute
        cil = "(allow httpd_t user_home_t (file (read)))"
        result = await load_module(mock_ssh, name="test", cil=cil, dry_run=False)
        assert result["status"] == "applied"
        assert result["verified_loaded"] is True


class TestRemoveModule:
    @pytest.mark.asyncio
    async def test_not_found(self, mock_ssh):
        async def mock_execute(cmd):
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "semodule" in cmd:
                return make_result("")
            return make_result("")

        mock_ssh.execute = mock_execute
        result = await remove_module(mock_ssh, name="nonexistent")
        assert result["status"] == "not_found"

    @pytest.mark.asyncio
    async def test_dry_run_preview(self, mock_ssh):
        async def mock_execute(cmd):
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "semodule -l" in cmd:
                return make_result("test_mod")
            return make_result("")

        mock_ssh.execute = mock_execute
        result = await remove_module(mock_ssh, name="test_mod", dry_run=True)
        assert result["status"] == "preview"

    @pytest.mark.asyncio
    async def test_apply_success(self, mock_ssh):
        call_count = 0

        async def mock_execute(cmd):
            nonlocal call_count
            call_count += 1
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "semodule -l" in cmd and call_count <= 2:
                return make_result("test_mod")
            if "semodule -r" in cmd:
                return make_result("")
            if "semodule -l" in cmd:
                return make_result("")
            return make_result("")

        mock_ssh.execute = mock_execute
        result = await remove_module(mock_ssh, name="test_mod", dry_run=False)
        assert result["status"] == "removed"


class TestSetFileContext:
    @pytest.mark.asyncio
    async def test_dry_run(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("Enforcing"))
        result = await set_file_context(
            mock_ssh, path="/home/user/web", context_type="httpd_sys_content_t"
        )
        assert result["status"] == "preview"
        assert "semanage fcontext" in result["commands"][0]

    @pytest.mark.asyncio
    async def test_apply_success(self, mock_ssh):
        async def mock_execute(cmd):
            if "getenforce" in cmd:
                return make_result("Enforcing")
            if "semanage fcontext" in cmd:
                return make_result("")
            if "restorecon" in cmd:
                return make_result("relabeled /home/user/web")
            return make_result("")

        mock_ssh.execute = mock_execute
        result = await set_file_context(
            mock_ssh,
            path="/home/user/web",
            context_type="httpd_sys_content_t",
            dry_run=False,
        )
        assert result["status"] == "applied"
