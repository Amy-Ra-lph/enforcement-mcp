# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""SPIFFE workload identity verification.

Verifies SPIFFE IDs (RFC 6920) for agentic workloads. Maps SPIFFE path
segments to auth policy claims so existing PolicyRule.matches_claims()
works unchanged.

Usage with linux-mcp auth_policy.yaml:

    rules:
      - host: "webserver*"
        tools: ["*"]
        claims:
          role: operator
          trust_domain: example.com
        action: ssh_default

A SPIFFE ID like `spiffe://example.com/operator/sre-agent` would match
because the SPIFFE verifier surfaces `role: operator` and
`trust_domain: example.com` as claims.
"""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger("linux-mcp-server")


class SPIFFEVerificationError(ValueError):
    pass


def verify_spiffe_id(
    spiffe_id: str,
    trust_domain: str,
) -> dict[str, Any]:
    """Verify a SPIFFE ID and return claims compatible with auth_policy.

    Returns a claims dict that can be passed directly to
    PolicyRule.matches_claims(), matching the same structure as JWT claims.

    Raises SPIFFEVerificationError if the ID is malformed or the trust
    domain doesn't match.
    """
    if not spiffe_id.startswith("spiffe://"):
        raise SPIFFEVerificationError("SPIFFE ID must start with spiffe://")

    stripped = spiffe_id[len("spiffe://"):]
    parts = stripped.split("/", 1)
    domain = parts[0]

    if not domain:
        raise SPIFFEVerificationError("SPIFFE ID has empty trust domain")

    if domain != trust_domain:
        raise SPIFFEVerificationError(
            f"Trust domain mismatch: got {domain}, expected {trust_domain}"
        )

    path = parts[1] if len(parts) > 1 else ""
    role = _role_from_path(path)

    return {
        "sub": spiffe_id,
        "iss": f"spiffe://{trust_domain}",
        "trust_domain": trust_domain,
        "role": role,
        "spiffe_path": path,
        "verified": True,
        "identity_type": "spiffe",
    }


def _role_from_path(path: str) -> str:
    """Extract role from SPIFFE path segments.

    Convention: first meaningful segment is the role.
    spiffe://domain/admin/agent-name → admin
    spiffe://domain/operator/sre-agent → operator
    spiffe://domain/viewer/dashboard → viewer
    """
    segments = [s.lower() for s in path.split("/") if s]
    if "admin" in segments:
        return "admin"
    if "operator" in segments or "ops" in segments:
        return "operator"
    if "containment" in segments or "incident-response" in segments:
        return "containment"
    return "viewer"
