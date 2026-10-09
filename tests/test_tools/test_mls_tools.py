"""Tests for MLS diagnosis tools."""

from unittest.mock import AsyncMock

import pytest

from enforcement_mcp.tools.mls import mls_categories, mls_file_level, mls_user_mappings
from tests.conftest import make_result


class TestMlsUserMappings:
    @pytest.mark.asyncio
    async def test_returns_mappings(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result(
            "Login Name           SELinux User         MLS/MCS Range        Service\n"
            "\n"
            "__default__          unconfined_u         s0-s0:c0.c1023       *\n"
            "root                 unconfined_u         s0-s0:c0.c1023       *\n"
        ))

        result = await mls_user_mappings(mock_ssh)
        assert len(result["mappings"]) == 2
        assert result["mappings"][0]["login"] == "__default__"


class TestMlsFileLevel:
    @pytest.mark.asyncio
    async def test_file(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result(
            "system_u:object_r:shadow_t:s0 /etc/shadow\n"
        ))

        result = await mls_file_level(mock_ssh, path="/etc/shadow")
        assert result["type"] == "shadow_t"
        assert result["level"] == "s0"

    @pytest.mark.asyncio
    async def test_no_input(self, mock_ssh):
        result = await mls_file_level(mock_ssh)
        assert result["error"] == "invalid_input"


class TestMlsCategories:
    @pytest.mark.asyncio
    async def test_returns_categories(self, mock_ssh):
        mock_ssh.execute = AsyncMock(side_effect=[
            make_result("s0\n"),
            make_result("c0\nc1\nc2\n"),
        ])

        result = await mls_categories(mock_ssh)
        assert len(result["categories"]) == 3
