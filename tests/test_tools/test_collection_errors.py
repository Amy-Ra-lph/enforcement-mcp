"""Tests for collection error handling (GH issue #4).

Verifies that failed ausearch commands return structured errors
instead of silently returning empty results.
"""

from unittest.mock import AsyncMock

import pytest

from enforcement_mcp.tools.fapolicyd import fapolicyd_denials
from enforcement_mcp.tools.manage_selinux import generate_module
from enforcement_mcp.tools.posture import host_posture, troubleshoot
from enforcement_mcp.tools.selinux import avc_denials
from tests.conftest import make_result


class TestAvcDenialsCollectionError:
    @pytest.mark.asyncio
    async def test_ausearch_failure_returns_collection_error(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("", stderr="ausearch: command not found", exit_code=127),
            ]
        )
        result = await avc_denials(mock_ssh, since="1h")
        assert "collection_error" in result
        assert result["collection_error"]["exit_code"] == 127
        assert result["total"] == 0

    @pytest.mark.asyncio
    async def test_ausearch_timeout_returns_collection_error(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("", exit_code=124),
            ]
        )
        result = await avc_denials(mock_ssh, since="1h")
        assert "collection_error" in result
        assert result["collection_error"]["exit_code"] == 124

    @pytest.mark.asyncio
    async def test_ausearch_no_matches_is_not_error(self, mock_ssh):
        """Exit code 1 = no matching records, not a failure."""
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("<no matches>", exit_code=1),
            ]
        )
        result = await avc_denials(mock_ssh, since="1h")
        assert "collection_error" not in result
        assert result["total"] == 0


class TestFapolicydDenialsCollectionError:
    @pytest.mark.asyncio
    async def test_ausearch_failure_returns_collection_error(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("fapolicyd-1.3.2-1.el9.x86_64"),
                make_result("", stderr="Permission denied", exit_code=2),
            ]
        )
        result = await fapolicyd_denials(mock_ssh, since="1h")
        assert "collection_error" in result
        assert result["collection_error"]["exit_code"] == 2
        assert result["total"] == 0


class TestGenerateModuleCollectionError:
    @pytest.mark.asyncio
    async def test_ausearch_failure_returns_error(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("", stderr="command not found", exit_code=127),
            ]
        )
        result = await generate_module(mock_ssh, name="test_fix", from_denials="1h")
        assert result["status"] == "collection_failed"


class TestTroubleshootCollectionError:
    @pytest.mark.asyncio
    async def test_collection_failure_lowers_confidence(self, mock_ssh):
        """When ausearch fails, troubleshoot must NOT say 'not_enforcement' with high confidence."""
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("", stderr="ausearch: command not found", exit_code=127),
                make_result("", exit_code=1),  # rpm -q fapolicyd → not installed
            ]
        )
        result = await troubleshoot(mock_ssh, symptom="app blocked", process="myapp")
        assert result["root_cause"] == "collection_incomplete"
        assert result["confidence"] == "low"
        assert "collection_errors" in result
        assert any("ausearch" in str(e) for e in result["collection_errors"])

    @pytest.mark.asyncio
    async def test_working_ausearch_still_reports_not_enforcement(self, mock_ssh):
        """When ausearch works but finds nothing, 'not_enforcement' high is correct."""
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("<no matches>", exit_code=1),
                make_result("", exit_code=1),  # rpm -q fapolicyd → not installed
            ]
        )
        result = await troubleshoot(mock_ssh, symptom="app blocked", process="myapp")
        assert result["root_cause"] == "not_enforcement"
        assert result["confidence"] == "high"
        assert "collection_errors" not in result

    @pytest.mark.asyncio
    async def test_partial_collection_failure(self, mock_ssh):
        """AVC collection fails but fapolicyd finds denials → still reports fapolicyd."""
        fanotify_raw = (
            "----\n"
            "type=FANOTIFY msg=audit(1760012521.456:789): resp=2 "
            "fan_type=1 fan_info=1 subj_trust=2 obj_trust=0 "
            'exe="/usr/bin/python3"\n'
        )
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("", stderr="permission denied", exit_code=2),
                make_result("fapolicyd-1.3.2-1.el9.x86_64"),
                make_result(fanotify_raw),
            ]
        )
        result = await troubleshoot(mock_ssh, symptom="app blocked", process="myapp")
        assert result["root_cause"] == "fapolicyd"
        assert result["confidence"] == "high"


class TestHostPostureCollectionError:
    @pytest.mark.asyncio
    async def test_ausearch_failure_noted_in_findings(self, mock_ssh):
        mock_ssh.execute = AsyncMock(
            side_effect=[
                make_result("Enforcing"),
                make_result("SELINUXTYPE=targeted"),
                make_result("", stderr="command not found", exit_code=127),
                make_result(""),  # semodule
                make_result("httpd_enable_homedirs --> off\n"),
                make_result("", exit_code=1),  # rpm -q fapolicyd
                make_result("__default__          unconfined_u         s0-s0:c0.c1023       *\n"),
            ]
        )
        result = await host_posture(mock_ssh)
        assert any("collection" in f.lower() or "COLLECTION" in f for f in result["findings"])
        assert "collection_errors" in result
