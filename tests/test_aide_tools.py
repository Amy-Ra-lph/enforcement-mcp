"""Tests for AIDE tools."""

from unittest.mock import AsyncMock

import pytest

from enforcement_mcp.ssh import CommandResult, SSHBackend
from enforcement_mcp.tools.aide import (
    aide_check,
    aide_config,
    aide_init_db,
    aide_update_db,
)


@pytest.fixture
def ssh():
    mock = AsyncMock(spec=SSHBackend)
    mock.host = "test-host"
    return mock


def _cmd_result(stdout="", stderr="", exit_code=0):
    return CommandResult(stdout=stdout, stderr=stderr, exit_code=exit_code)


class TestAideCheck:
    async def test_returns_not_installed(self, ssh):
        ssh.execute.return_value = _cmd_result(exit_code=1)  # rpm -q aide fails
        result = await aide_check(ssh)
        assert result["error"] == "aide_not_installed"

    async def test_returns_no_database(self, ssh):
        ssh.execute.side_effect = [
            _cmd_result(stdout="aide-0.16-1.el10.x86_64"),  # rpm -q aide
            _cmd_result(exit_code=1),  # test -f db
        ]
        result = await aide_check(ssh)
        assert result["error"] == "aide_no_database"

    async def test_returns_clean_check(self, ssh):
        ssh.execute.side_effect = [
            _cmd_result(stdout="aide-0.16-1.el10.x86_64"),  # rpm check
            _cmd_result(exit_code=0),  # db exists
            _cmd_result(stdout="AIDE found NO differences\n\nTotal number of entries:\t50000"),
        ]
        result = await aide_check(ssh)
        assert result["added"] == 0
        assert result["total_files_checked"] == 50000

    async def test_returns_changes(self, ssh):
        stdout = (
            "Summary:\n  Added entries:           1\n"
            "  Removed entries:         0\n  Changed entries:         2\n"
            "\nTotal number of entries:\t100\n"
            "\nAdded entries:\n\n/tmp/new\n"
            "\nChanged entries:\n\n/etc/passwd\n/etc/shadow\n"
        )
        ssh.execute.side_effect = [
            _cmd_result(stdout="aide-0.16"),
            _cmd_result(exit_code=0),
            _cmd_result(stdout=stdout, exit_code=1),
        ]
        result = await aide_check(ssh)
        assert result["added"] == 1
        assert result["changed"] == 2
        assert len(result["changes"]) == 3


class TestAideConfig:
    async def test_returns_parsed_config(self, ssh):
        conf = (
            "database=file:/var/lib/aide/aide.db.gz\n"
            "database_out=file:/var/lib/aide/aide.db.new.gz\n"
            "NORMAL = p+i+n+u+g\n"
            "/etc NORMAL\n"
            "/boot NORMAL\n"
        )
        ssh.execute.side_effect = [
            _cmd_result(stdout="aide-0.16"),
            _cmd_result(stdout=conf),
        ]
        result = await aide_config(ssh)
        assert result["database_path"] == "file:/var/lib/aide/aide.db.gz"
        assert len(result["rules"]) == 2


class TestAideInitDb:
    async def test_dry_run(self, ssh):
        ssh.execute.return_value = _cmd_result(stdout="aide-0.16")
        result = await aide_init_db(ssh, dry_run=True)
        assert result["dry_run"] is True
        assert "aide --init" in result["command"]

    async def test_execute(self, ssh):
        ssh.execute.side_effect = [
            _cmd_result(stdout="aide-0.16"),
            _cmd_result(stdout="AIDE initialized"),
            _cmd_result(exit_code=0),
        ]
        result = await aide_init_db(ssh, dry_run=False)
        assert result["status"] == "initialized"


class TestAideUpdateDb:
    async def test_dry_run(self, ssh):
        ssh.execute.return_value = _cmd_result(stdout="aide-0.16")
        result = await aide_update_db(ssh, dry_run=True)
        assert result["dry_run"] is True

    async def test_execute(self, ssh):
        stdout = "Summary:\n  Added entries:           0\n  Removed entries:         0\n  Changed entries:         1\nTotal number of entries:\t100\n"
        ssh.execute.side_effect = [
            _cmd_result(stdout="aide-0.16"),
            _cmd_result(stdout=stdout, exit_code=1),
            _cmd_result(exit_code=0),
        ]
        result = await aide_update_db(ssh, dry_run=False)
        assert result["status"] == "updated"
