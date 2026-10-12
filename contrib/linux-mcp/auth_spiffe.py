# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""SPIFFE/WID auth provider for linux-mcp.

Extends linux-mcp's auth.py with SPIFFE workload identity support.
Integrates with the existing AuthProvider enum and create_auth_provider()
function.

To integrate, add to linux-mcp's config.py:

    class AuthProvider(StrEnum):
        GOOGLE = "google"
        GITHUB = "github"
        JWT = "jwt"
        INTROSPECTION = "introspection"
        SPIFFE = "spiffe"              # ← NEW

    class SPIFFEAuthConfig(BaseSettings):
        trust_domain: str
        workload_api_socket: str | None = None
        require_svid: bool = False

    class AuthConfig(BaseSettings):
        ...
        spiffe: SPIFFEAuthConfig | None = None  # ← NEW

Then add to auth.py's create_auth_provider():

    elif CONFIG.auth.provider == AuthProvider.SPIFFE:
        from .auth_spiffe import create_spiffe_provider
        return create_spiffe_provider(CONFIG.auth.spiffe, base_url)
"""

from __future__ import annotations

import logging
from typing import Any

from fastmcp.server.auth.providers.bearer import BearerAuthProvider
from pydantic import BaseModel

from .identity.spiffe import SPIFFEVerificationError, verify_spiffe_id


logger = logging.getLogger("linux-mcp-server")


class SPIFFEAuthConfig(BaseModel):
    """SPIFFE auth configuration (for linux-mcp config.py integration)."""
    trust_domain: str
    workload_api_socket: str | None = None
    require_svid: bool = False


class SPIFFETokenVerifier:
    """Token verifier that accepts SPIFFE IDs.

    Implements the interface expected by FastMCP's BearerAuthProvider:
    - verify_token(token) → claims dict or raises
    """

    def __init__(self, trust_domain: str):
        self.trust_domain = trust_domain

    async def verify_token(self, token: str) -> dict[str, Any]:
        """Verify a SPIFFE ID token and return claims.

        Returns claims in the same format as JWT tokens so that
        auth_policy.yaml rules work identically for both.
        """
        try:
            claims = verify_spiffe_id(token, self.trust_domain)
            return claims
        except SPIFFEVerificationError as e:
            raise ValueError(str(e)) from e


def create_spiffe_provider(
    config: SPIFFEAuthConfig,
    base_url: str | None = None,
) -> BearerAuthProvider:
    """Create a FastMCP auth provider for SPIFFE/WID identity.

    Returns a BearerAuthProvider that accepts SPIFFE IDs in the
    Authorization: Bearer header. The verified claims are then
    available to auth_policy rules via PolicyRule.matches_claims().

    Example auth_policy.yaml:
        rules:
          - host: "*"
            tools: ["*"]
            claims:
              role: operator
              trust_domain: example.com
            action: ssh_default
    """
    verifier = SPIFFETokenVerifier(config.trust_domain)

    return BearerAuthProvider(
        token_verifier=verifier,
    )
