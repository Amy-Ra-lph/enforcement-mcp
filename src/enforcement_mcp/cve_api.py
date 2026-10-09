"""Red Hat Security Data API client.

Direct HTTPS calls to access.redhat.com/hydra/rest/securitydata/ — no auth required.
No dependency on Trentina or any internal tooling, so this works in customer environments.
"""

import asyncio
import contextlib
import json
import urllib.request
from urllib.error import HTTPError, URLError

from enforcement_mcp.models.cve import CveDetail

_BASE_URL = "https://access.redhat.com/hydra/rest/securitydata"


def _fetch_cve_sync(cve_id: str) -> dict:
    """Synchronous CVE fetch — called via asyncio.to_thread()."""
    url = f"{_BASE_URL}/cve/{cve_id}.json"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
    except HTTPError as e:
        if e.code == 404:
            return {"error": "not_found", "cve_id": cve_id}
        return {"error": f"http_{e.code}", "cve_id": cve_id}
    except URLError as e:
        return {"error": "network", "detail": str(e.reason), "cve_id": cve_id}


async def fetch_cve(cve_id: str) -> dict:
    """Fetch CVE data from Red Hat Security Data API."""
    return await asyncio.to_thread(_fetch_cve_sync, cve_id)


def parse_cve_response(raw: dict) -> CveDetail | None:
    """Parse Red Hat CVE API response into CveDetail model."""
    if "error" in raw:
        return None

    severity = "unknown"
    cvss3_score = None

    cvss3 = raw.get("cvss3", {})
    if isinstance(cvss3, dict):
        cvss3_score = cvss3.get("cvss3_base_score")
        if cvss3_score:
            cvss3_score = float(cvss3_score)
    elif isinstance(cvss3, str) and "/" in cvss3:
        with contextlib.suppress(ValueError):
            cvss3_score = float(cvss3.split("/")[0])

    threat_severity = raw.get("threat_severity", "").lower()
    if threat_severity in ("low", "moderate", "important", "critical"):
        severity = threat_severity

    affected = []
    fixed_in = []
    for state_entry in raw.get("affected_release", []):
        if isinstance(state_entry, dict):
            pkg = state_entry.get("package", "")
            if pkg:
                fixed_in.append(pkg)
    for state_entry in raw.get("package_state", []):
        if isinstance(state_entry, dict):
            pkg = state_entry.get("package_name", "")
            if pkg:
                affected.append(pkg)

    cwe = None
    cwe_raw = raw.get("cwe", "")
    if isinstance(cwe_raw, str) and cwe_raw.startswith("CWE-"):
        cwe = cwe_raw

    details = raw.get("details", [])
    description = details[0] if isinstance(details, list) and details else str(details)

    return CveDetail(
        cve_id=raw.get("name", raw.get("CVE", "")),
        severity=severity,
        cvss3_score=cvss3_score,
        description=description[:500],
        affected_packages=affected[:20],
        fixed_in=fixed_in[:20],
        cwe=cwe,
        public_date=raw.get("public_date"),
    )
