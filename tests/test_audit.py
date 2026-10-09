"""Tests for audit trail."""

from unittest.mock import AsyncMock

import pytest

from enforcement_mcp.audit import AUDIT_PATH, _sanitize_params, write_audit_entry
from enforcement_mcp.models.identity import CallerIdentity, Role
from tests.conftest import make_result


def _make_caller(subject: str = "test-agent") -> CallerIdentity:
    return CallerIdentity(
        subject=subject,
        issuer="test",
        roles=[Role.OPERATOR],
        verified=True,
    )


class TestSanitizeParams:
    def test_redacts_token(self):
        result = _sanitize_params({"identity_token": "secret123", "name": "httpd"})
        assert result["identity_token"] == "***REDACTED***"
        assert result["name"] == "httpd"

    def test_redacts_password(self):
        result = _sanitize_params({"password": "hunter2"})
        assert result["password"] == "***REDACTED***"

    def test_redacts_secret(self):
        result = _sanitize_params({"secret": "classified"})
        assert result["secret"] == "***REDACTED***"

    def test_truncates_long_strings(self):
        long_value = "x" * 600
        result = _sanitize_params({"cil": long_value})
        assert len(result["cil"]) < 520
        assert result["cil"].endswith("...[truncated]")

    def test_preserves_normal_params(self):
        result = _sanitize_params({"name": "httpd_enable_homedirs", "value": True})
        assert result == {"name": "httpd_enable_homedirs", "value": True}


class TestWriteAuditEntry:
    @pytest.mark.asyncio
    async def test_writes_to_remote(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result(""))
        entry = await write_audit_entry(
            mock_ssh,
            caller=_make_caller(),
            tool="manage.set_boolean",
            parameters={"name": "httpd_enable_homedirs", "value": True},
            risk_score=18,
            risk_level="low",
            result_status="applied",
            identity_mode="oauth",
            authz_decision="authorized",
        )
        assert entry.tool == "manage.set_boolean"
        assert entry.caller == "test-agent"
        assert entry.risk_score == 18
        mock_ssh.execute.assert_called_once()
        cmd = mock_ssh.execute.call_args[0][0]
        assert AUDIT_PATH in cmd
        assert "mkdir -p" in cmd

    @pytest.mark.asyncio
    async def test_redacts_token_in_audit(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result(""))
        entry = await write_audit_entry(
            mock_ssh,
            caller=_make_caller(),
            tool="manage.load_module",
            parameters={"identity_token": "secret", "name": "test_module"},
            result_status="applied",
            identity_mode="oauth",
            authz_decision="authorized",
        )
        assert entry.parameters["identity_token"] == "***REDACTED***"

    @pytest.mark.asyncio
    async def test_survives_write_failure(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result("", "Permission denied", 1))
        entry = await write_audit_entry(
            mock_ssh,
            caller=_make_caller(),
            tool="manage.set_boolean",
            parameters={"name": "test"},
            result_status="applied",
            identity_mode="none",
            authz_decision="authorized",
        )
        assert entry.tool == "manage.set_boolean"

    @pytest.mark.asyncio
    async def test_survives_connection_error(self, mock_ssh):
        mock_ssh.execute = AsyncMock(side_effect=ConnectionError("lost"))
        entry = await write_audit_entry(
            mock_ssh,
            caller=_make_caller(),
            tool="diagnosis.troubleshoot",
            parameters={"symptom": "blocked"},
            result_status="success",
            identity_mode="none",
            authz_decision="authorized",
        )
        assert entry.tool == "diagnosis.troubleshoot"

    @pytest.mark.asyncio
    async def test_entry_has_timestamp(self, mock_ssh):
        mock_ssh.execute = AsyncMock(return_value=make_result(""))
        entry = await write_audit_entry(
            mock_ssh,
            caller=_make_caller(),
            tool="diagnosis.host_posture",
            parameters={},
            result_status="success",
            identity_mode="none",
            authz_decision="authorized",
        )
        assert "T" in entry.timestamp
