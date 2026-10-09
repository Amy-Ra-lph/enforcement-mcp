"""Tests for Red Hat Security Data API client."""

from unittest.mock import patch

from enforcement_mcp.cve_api import _fetch_cve_sync, parse_cve_response


class TestParseCveResponse:
    def test_parses_full_response(self):
        raw = {
            "name": "CVE-2024-6387",
            "threat_severity": "Important",
            "cvss3": {"cvss3_base_score": "8.1"},
            "details": ["A race condition in sshd signal handling."],
            "affected_release": [
                {"package": "openssh-9.6p1-1.el9"},
            ],
            "package_state": [
                {"package_name": "openssh"},
            ],
            "cwe": "CWE-364",
            "public_date": "2024-07-01",
        }

        result = parse_cve_response(raw)
        assert result is not None
        assert result.cve_id == "CVE-2024-6387"
        assert result.severity == "important"
        assert result.cvss3_score == 8.1
        assert "openssh" in result.affected_packages
        assert "openssh-9.6p1-1.el9" in result.fixed_in
        assert result.cwe == "CWE-364"

    def test_handles_error_response(self):
        raw = {"error": "not_found", "cve_id": "CVE-9999-0000"}
        result = parse_cve_response(raw)
        assert result is None

    def test_handles_missing_fields(self):
        raw = {"name": "CVE-2024-0001", "details": ["Something."]}
        result = parse_cve_response(raw)
        assert result is not None
        assert result.cve_id == "CVE-2024-0001"
        assert result.severity == "unknown"
        assert result.cvss3_score is None

    def test_handles_cvss3_string_format(self):
        raw = {
            "name": "CVE-2024-0002",
            "cvss3": "7.5/CVSS:3.1/AV:N",
            "details": ["test"],
        }
        result = parse_cve_response(raw)
        assert result is not None
        assert result.cvss3_score == 7.5

    def test_handles_empty_details(self):
        raw = {"name": "CVE-2024-0003", "details": []}
        result = parse_cve_response(raw)
        assert result is not None
        assert result.description == "[]"

    def test_truncates_long_description(self):
        raw = {"name": "CVE-2024-0004", "details": ["x" * 1000]}
        result = parse_cve_response(raw)
        assert result is not None
        assert len(result.description) == 500


class TestFetchCveSync:
    @patch("enforcement_mcp.cve_api.urllib.request.urlopen")
    def test_404_returns_not_found(self, mock_urlopen):
        from urllib.error import HTTPError

        mock_urlopen.side_effect = HTTPError(
            url="", code=404, msg="Not Found", hdrs=None, fp=None  # type: ignore[arg-type]
        )
        result = _fetch_cve_sync("CVE-9999-0000")
        assert result["error"] == "not_found"

    @patch("enforcement_mcp.cve_api.urllib.request.urlopen")
    def test_network_error(self, mock_urlopen):
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("Connection refused")
        result = _fetch_cve_sync("CVE-2024-0001")
        assert result["error"] == "network"
