"""Tests for SSH backend."""

from unittest.mock import MagicMock

import pytest

from enforcement_mcp.ssh import CommandResult, SSHBackend


class TestCommandResult:
    def test_success(self):
        r = CommandResult(stdout="Enforcing\n", stderr="", exit_code=0)
        assert r.success is True
        assert r.stdout_stripped == "Enforcing"

    def test_failure(self):
        r = CommandResult(stdout="", stderr="command not found", exit_code=127)
        assert r.success is False


class TestSSHBackend:
    @pytest.mark.asyncio
    async def test_execute_returns_command_result(self):
        backend = SSHBackend(host="testhost", user="root")
        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.read.return_value = b"Enforcing\n"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        backend._client = mock_client
        result = await backend.execute("getenforce")

        assert result.stdout_stripped == "Enforcing"
        assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_not_connected_raises(self):
        backend = SSHBackend(host="testhost", user="root")
        with pytest.raises(ConnectionError, match="Not connected"):
            await backend.execute("getenforce")
