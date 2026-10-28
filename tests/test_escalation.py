"""Tests for the escalation (sudo-like) system."""

import contextlib
import hashlib
import time
from unittest.mock import MagicMock

import pytest

from enforcement_mcp import server


@pytest.fixture(autouse=True)
def _reset_escalation():
    """Reset escalation state between tests."""
    orig_hash = server._escalation_passphrase_hash
    orig_timeout = server._escalation_timeout
    orig_sessions = server._escalated_sessions.copy()
    yield
    server._escalation_passphrase_hash = orig_hash
    server._escalation_timeout = orig_timeout
    server._escalated_sessions.clear()
    server._escalated_sessions.update(orig_sessions)
    with contextlib.suppress(Exception):
        server.mcp.remove_tool("manage.escalate")


def _make_ctx(session_id: str = "test-session") -> MagicMock:
    ctx = MagicMock()
    ctx.session_id = session_id
    return ctx


class TestCheckEscalation:
    def test_no_passphrase_configured_allows_all(self):
        server._escalation_passphrase_hash = None
        assert server._check_escalation(None) is None
        assert server._check_escalation(_make_ctx()) is None

    def test_passphrase_configured_blocks_without_escalation(self):
        server._escalation_passphrase_hash = hashlib.sha256(b"secret").digest()
        result = server._check_escalation(_make_ctx())
        assert result["error"] == "escalation_required"

    def test_escalated_session_allowed(self):
        server._escalation_passphrase_hash = hashlib.sha256(b"secret").digest()
        server._escalated_sessions["test-session"] = time.time() + 3600
        assert server._check_escalation(_make_ctx()) is None

    def test_expired_escalation_blocked(self):
        server._escalation_passphrase_hash = hashlib.sha256(b"secret").digest()
        server._escalated_sessions["test-session"] = time.time() - 1
        result = server._check_escalation(_make_ctx())
        assert result["error"] == "escalation_required"
        assert "test-session" not in server._escalated_sessions

    def test_different_session_blocked(self):
        server._escalation_passphrase_hash = hashlib.sha256(b"secret").digest()
        server._escalated_sessions["other-session"] = time.time() + 3600
        result = server._check_escalation(_make_ctx("test-session"))
        assert result["error"] == "escalation_required"

    def test_no_ctx_uses_default_key(self):
        server._escalation_passphrase_hash = hashlib.sha256(b"secret").digest()
        server._escalated_sessions["__default__"] = time.time() + 3600
        assert server._check_escalation(None) is None


class TestSetEscalationConfig:
    def test_sets_passphrase_hash(self):
        server.set_escalation_config("my-secret", timeout=600)
        expected = hashlib.sha256(b"my-secret").digest()
        assert server._escalation_passphrase_hash == expected
        assert server._escalation_timeout == 600

    def test_registers_escalate_tool(self):
        server.set_escalation_config("test-pass")
        tools = [t.name for t in pytest.importorskip("asyncio").run(server.mcp.list_tools())]
        assert "manage.escalate" in tools


class TestEscalateToolE2E:
    @pytest.mark.asyncio
    async def test_correct_passphrase_escalates(self):
        server.set_escalation_config("correct-horse", timeout=900)

        tools = await server.mcp.list_tools()
        assert any(t.name == "manage.escalate" for t in tools)

        result = await server.mcp.call_tool(
            "manage.escalate",
            {"passphrase": "correct-horse", "reason": "test"},
        )
        content = result.content[0].text
        assert "escalated" in content
        assert not result.is_error

    @pytest.mark.asyncio
    async def test_wrong_passphrase_denied(self):
        server.set_escalation_config("correct-horse")
        result = await server.mcp.call_tool(
            "manage.escalate",
            {"passphrase": "wrong-horse", "reason": "test"},
        )
        content = result.content[0].text
        assert "denied" in content
