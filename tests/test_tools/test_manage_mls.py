"""Tests for MLS management tools."""

from unittest.mock import AsyncMock

import pytest

from enforcement_mcp.tools.manage_mls import mls_assign_category, mls_set_user_range
from tests.conftest import make_result


class TestMlsAssignCategory:
    @pytest.mark.asyncio
    async def test_missing_categories(self, mock_ssh):
        result = await mls_assign_category(mock_ssh, path="/data", categories=[])
        assert result["error"] == "missing_categories"

    @pytest.mark.asyncio
    async def test_dry_run_preview(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            return_value=make_result(
                "system_u:object_r:default_t:s0 /data/classified"
            )
        )
        result = await mls_assign_category(
            mock_ssh, path="/data/classified", categories=["c5", "c10"], dry_run=True
        )
        assert result["status"] == "preview"
        assert "chcat" in result["command"]
        assert result["categories"] == ["c5", "c10"]

    @pytest.mark.asyncio
    async def test_apply_success(self, mock_ssh):
        call_count = 0

        async def mock_execute(cmd):
            nonlocal call_count
            call_count += 1
            if "ls -dZ" in cmd and call_count == 1:
                return make_result(
                    "system_u:object_r:default_t:s0 /data/classified"
                )
            if "chcat" in cmd:
                return make_result("")
            if "ls -dZ" in cmd:
                return make_result(
                    "system_u:object_r:default_t:s0:c5,c10 /data/classified"
                )
            return make_result("")

        mock_ssh.execute = mock_execute
        result = await mls_assign_category(
            mock_ssh,
            path="/data/classified",
            categories=["c5", "c10"],
            dry_run=False,
        )
        assert result["status"] == "applied"
        assert "c5,c10" in result["new_context"]

    @pytest.mark.asyncio
    async def test_recursive_flag(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            return_value=make_result("system_u:object_r:default_t:s0 /data")
        )
        result = await mls_assign_category(
            mock_ssh,
            path="/data",
            categories=["c5"],
            recursive=True,
            dry_run=True,
        )
        assert "-R" in result["command"]


class TestMlsSetUserRange:
    @pytest.mark.asyncio
    async def test_root_restriction_blocked(self, mock_ssh):
        result = await mls_set_user_range(
            mock_ssh, login="root", range_spec="s0:c5"
        )
        assert result["status"] == "blocked"
        assert "lockout" in result["reason"].lower()

    @pytest.mark.asyncio
    async def test_root_full_range_allowed(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            return_value=make_result(
                "root             unconfined_u         s0-s0:c0.c1023"
            )
        )
        result = await mls_set_user_range(
            mock_ssh, login="root", range_spec="s0-s0:c0.c1023", dry_run=True
        )
        assert result["status"] == "preview"

    @pytest.mark.asyncio
    async def test_user_not_found(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result(""))
        result = await mls_set_user_range(
            mock_ssh, login="nonexistent", range_spec="s0:c5"
        )
        assert result["status"] == "not_found"

    @pytest.mark.asyncio
    async def test_dry_run_preview(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            return_value=make_result(
                "contractor       user_u               s0-s0:c0.c1023       *"
            )
        )
        result = await mls_set_user_range(
            mock_ssh, login="contractor", range_spec="s0:c5,c10", dry_run=True
        )
        assert result["status"] == "preview"
        assert result["current_range"] == "s0-s0:c0.c1023"
        assert result["new_range"] == "s0:c5,c10"

    @pytest.mark.asyncio
    async def test_apply_success(self, mock_ssh):
        call_count = 0

        async def mock_execute(cmd):
            nonlocal call_count
            call_count += 1
            if "semanage login -l" in cmd and call_count == 1:
                return make_result(
                    "contractor       user_u               s0-s0:c0.c1023       *"
                )
            if "semanage login -m" in cmd:
                return make_result("")
            if "semanage login -l" in cmd:
                return make_result(
                    "contractor       user_u               s0:c5,c10            *"
                )
            return make_result("")

        mock_ssh.execute = mock_execute
        result = await mls_set_user_range(
            mock_ssh, login="contractor", range_spec="s0:c5,c10", dry_run=False
        )
        assert result["status"] == "applied"
        assert result["verified_range"] == "s0:c5,c10"
