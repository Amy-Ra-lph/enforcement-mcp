"""Tests for offline text-input mode tools."""

import pytest

from enforcement_mcp.tools.fapolicyd import fapolicyd_denials
from enforcement_mcp.tools.offline import parse_denials
from enforcement_mcp.tools.posture import troubleshoot
from enforcement_mcp.tools.selinux import avc_denials

SAMPLE_AVC = """\
time->Wed Oct  9 14:23:01 2026
type=AVC msg=audit(1696862581.123:456): avc:  denied  { read } for  pid=1234 comm="httpd" name="index.html" \
scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0
time->Wed Oct  9 14:23:05 2026
type=AVC msg=audit(1696862585.456:457): avc:  denied  { write } for  pid=1234 comm="httpd" name="upload.tmp" \
scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:tmp_t:s0 tclass=file permissive=0
time->Wed Oct  9 14:25:00 2026
type=AVC msg=audit(1696862700.789:458): avc:  denied  { name_connect } for  pid=5678 comm="nginx" \
scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:http_port_t:s0 tclass=tcp_socket permissive=0
"""

SAMPLE_FANOTIFY = """\
time->Wed Oct  9 14:30:00 2026
type=FANOTIFY msg=audit(1696863000.111:500): resp=2 pid=9999 uid=1000 exe="/tmp/suspicious_binary" \
subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 obj_trust=0
"""

EMPTY_TEXT = "<no matches>"


class TestParseDenials:
    def test_auto_avc_only(self):
        result = parse_denials(SAMPLE_AVC)
        assert result["total"] == 3
        assert result["summary"]["avc_count"] == 3
        assert result["summary"]["fanotify_count"] == 0
        assert "httpd_t" in result["summary"]["top_source_types"]

    def test_auto_fanotify_only(self):
        result = parse_denials(SAMPLE_FANOTIFY)
        assert result["total"] == 1
        assert result["summary"]["fanotify_count"] == 1

    def test_auto_mixed(self):
        result = parse_denials(SAMPLE_AVC + "\n" + SAMPLE_FANOTIFY)
        assert result["total"] == 4
        assert result["summary"]["avc_count"] == 3
        assert result["summary"]["fanotify_count"] == 1

    def test_avc_type_filter(self):
        result = parse_denials(SAMPLE_FANOTIFY, denial_type="avc")
        assert result["summary"]["avc_count"] == 0
        assert result["summary"]["fanotify_count"] == 0

    def test_fanotify_type_filter(self):
        result = parse_denials(SAMPLE_AVC, denial_type="fanotify")
        assert result["summary"]["avc_count"] == 0

    def test_empty_input(self):
        result = parse_denials("")
        assert result["total"] == 0
        assert result["error"] == "empty_input"

    def test_no_matches(self):
        result = parse_denials(EMPTY_TEXT)
        assert result["total"] == 0

    def test_permissions_summary(self):
        result = parse_denials(SAMPLE_AVC)
        assert "read" in result["summary"]["permissions"]
        assert "write" in result["summary"]["permissions"]

    def test_source_raw_text(self):
        result = parse_denials(SAMPLE_AVC)
        assert result["source"] == "raw_text"


class TestAvcDenialsRawText:
    @pytest.mark.asyncio
    async def test_raw_text_no_ssh(self):
        result = await avc_denials(None, raw_text=SAMPLE_AVC)
        assert result["total"] == 3
        assert result["mode"] == "offline"
        assert result["source"] == "raw_text"

    @pytest.mark.asyncio
    async def test_raw_text_source_filter(self):
        result = await avc_denials(None, source_type="httpd_t", raw_text=SAMPLE_AVC)
        assert result["total"] == 3
        assert all(d["source_type"] == "httpd_t" for d in result["denials"])

    @pytest.mark.asyncio
    async def test_raw_text_empty(self):
        result = await avc_denials(None, raw_text=EMPTY_TEXT)
        assert result["total"] == 0
        assert result["mode"] == "offline"


class TestFapolicydDenialsRawText:
    @pytest.mark.asyncio
    async def test_raw_text_no_ssh(self):
        result = await fapolicyd_denials(None, raw_text=SAMPLE_FANOTIFY)
        assert result["total"] == 1
        assert result["source"] == "raw_text"

    @pytest.mark.asyncio
    async def test_raw_text_empty(self):
        result = await fapolicyd_denials(None, raw_text=EMPTY_TEXT)
        assert result["total"] == 0


class TestTroubleshootOffline:
    @pytest.mark.asyncio
    async def test_offline_avc_only(self):
        result = await troubleshoot(
            None, symptom="httpd blocked", raw_avc_text=SAMPLE_AVC,
        )
        assert result["root_cause"] == "selinux"
        assert result["confidence"] == "high"
        assert any("raw" in s["step"].lower() for s in result["chain"])

    @pytest.mark.asyncio
    async def test_offline_fanotify_only(self):
        result = await troubleshoot(
            None, symptom="binary blocked", raw_fanotify_text=SAMPLE_FANOTIFY,
        )
        assert result["root_cause"] == "fapolicyd"
        assert result["confidence"] == "high"

    @pytest.mark.asyncio
    async def test_offline_no_denials(self):
        result = await troubleshoot(
            None, symptom="something blocked", raw_avc_text=EMPTY_TEXT,
        )
        assert result["root_cause"] == "not_enforcement"

    @pytest.mark.asyncio
    async def test_offline_process_filter(self):
        result = await troubleshoot(
            None, symptom="httpd blocked", process="httpd",
            raw_avc_text=SAMPLE_AVC,
        )
        assert result["root_cause"] == "selinux"
        assert len(result["denials_found"]) > 0

    @pytest.mark.asyncio
    async def test_offline_mixed(self):
        result = await troubleshoot(
            None, symptom="something blocked",
            raw_avc_text=SAMPLE_AVC, raw_fanotify_text=SAMPLE_FANOTIFY,
        )
        assert result["root_cause"] == "selinux"
        assert len(result["denials_found"]) == 4
