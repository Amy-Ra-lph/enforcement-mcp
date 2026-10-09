"""Shared fixtures for enforcement-mcp tests."""

from unittest.mock import AsyncMock

import pytest

from enforcement_mcp.ssh import CommandResult, SSHBackend


@pytest.fixture
def mock_ssh():
    """Create a mock SSH backend with configurable command responses."""
    backend = SSHBackend(host="testhost.example.com", user="root")
    backend._client = AsyncMock()
    return backend


def make_result(stdout: str, stderr: str = "", exit_code: int = 0) -> CommandResult:
    """Helper to create CommandResult for tests."""
    return CommandResult(stdout=stdout, stderr=stderr, exit_code=exit_code)
