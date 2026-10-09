"""Tests for fapolicyd diagnosis tools."""

from unittest.mock import AsyncMock

import pytest

from enforcement_mcp.tools.fapolicyd import (
    fapolicyd_rules,
    fapolicyd_status,
    fapolicyd_trust_check,
)
from tests.conftest import make_result


class TestFapolicydStatus:
    @pytest.mark.asyncio
    async def test_active(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("", exit_code=0),
                make_result("active"),
                make_result("15"),
                make_result("48231"),
            ]
        )

        result = await fapolicyd_status(mock_ssh)
        assert result["active"] is True
        assert result["rules"] == 15

    @pytest.mark.asyncio
    async def test_not_installed(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            return_value=make_result("package fapolicyd is not installed", exit_code=1)
        )

        result = await fapolicyd_status(mock_ssh)
        assert result["error"] == "fapolicyd_not_installed"


class TestFapolicydTrustCheck:
    @pytest.mark.asyncio
    async def test_trusted_in_db(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("", exit_code=0),
                make_result("rpmdb /usr/bin/ls 123456 abc123\n"),
            ]
        )

        result = await fapolicyd_trust_check(mock_ssh, path="/usr/bin/ls")
        assert result["trusted"] is True

    @pytest.mark.asyncio
    async def test_untrusted(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("", exit_code=0),
                make_result("", exit_code=1),
                make_result("file /tmp/payload is not owned by any package", exit_code=1),
            ]
        )

        result = await fapolicyd_trust_check(mock_ssh, path="/tmp/payload")
        assert result["trusted"] is False


class TestFapolicydRules:
    @pytest.mark.asyncio
    async def test_returns_rules(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("", exit_code=0),
                make_result(
                    "1. deny perm=execute all : all\n2. allow perm=any uid=0 : dir=/usr/\n"
                ),
            ]
        )

        result = await fapolicyd_rules(mock_ssh)
        assert result["total"] == 2
