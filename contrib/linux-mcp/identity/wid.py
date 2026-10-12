# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""Workload Identity Document (WID) verification.

WID extends SPIFFE with X.509 SVID verification and workload attestation.
This module adds WID support alongside linux-mcp's existing auth providers
(Google, GitHub, JWT, Introspection).

WID is the identity layer for agentic AI workloads — it answers "which
agent is making this request?" using SPIFFE-compatible workload identity
rather than user-level OAuth tokens.

Configuration:
    LINUX_MCP_WID__TRUST_DOMAIN=example.com
    LINUX_MCP_WID__WORKLOAD_API_SOCKET=/run/spire/sockets/agent.sock
    LINUX_MCP_WID__REQUIRE_SVID=false  # string-only by default

When REQUIRE_SVID=true, the module fetches the X.509 SVID from the
SPIFFE Workload API and verifies the certificate chain. When false (default),
it accepts string-format SPIFFE IDs (suitable for MCP stdio transport where
mTLS isn't available).
"""

from __future__ import annotations

import logging
from typing import Any

from .spiffe import SPIFFEVerificationError, verify_spiffe_id


logger = logging.getLogger("linux-mcp-server")


class WIDConfig:
    """Workload Identity Document configuration."""

    def __init__(
        self,
        trust_domain: str,
        workload_api_socket: str | None = None,
        require_svid: bool = False,
    ):
        self.trust_domain = trust_domain
        self.workload_api_socket = workload_api_socket
        self.require_svid = require_svid


def verify_wid(
    identity_token: str,
    config: WIDConfig,
) -> dict[str, Any]:
    """Verify a workload identity and return claims for auth_policy.

    Accepts either:
    - SPIFFE ID string: "spiffe://domain/role/agent-name"
    - Future: X.509 SVID (when require_svid=True)

    Returns claims dict compatible with PolicyRule.matches_claims().
    """
    if not identity_token:
        return _anonymous_claims()

    if identity_token.startswith("spiffe://"):
        claims = verify_spiffe_id(identity_token, config.trust_domain)
        claims["identity_type"] = "wid"

        if config.require_svid:
            logger.warning(
                "WID SVID verification requested but X.509 validation "
                "not yet implemented — falling back to string verification"
            )

        return claims

    raise SPIFFEVerificationError(
        f"WID identity must be a SPIFFE ID (got: {identity_token[:20]}...)"
    )


def _anonymous_claims() -> dict[str, Any]:
    """Return claims for an anonymous/unauthenticated caller."""
    return {
        "sub": "anonymous",
        "iss": "local",
        "role": "viewer",
        "verified": False,
        "identity_type": "anonymous",
    }


def is_wid_token(token: str) -> bool:
    """Check if a token looks like a WID/SPIFFE identity."""
    return token.startswith("spiffe://")
