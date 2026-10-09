"""Configuration for enforcement-mcp."""

import os

from pydantic import BaseModel

from .models.identity import AuthzPolicy, IdentityMode


class HostConfig(BaseModel):
    """SSH target host configuration."""

    host: str
    user: str = "root"
    port: int = 22
    key_file: str | None = None


class IdentityConfig(BaseModel):
    """Identity verification configuration."""

    mode: IdentityMode = IdentityMode.NONE
    authz_policy: AuthzPolicy = AuthzPolicy.PERMISSIVE
    oauth_issuer: str = ""
    oauth_audience: str = ""
    oauth_jwks_uri: str = ""
    spiffe_trust_domain: str = ""
    spiffe_socket: str = ""


def get_host_config() -> HostConfig:
    """Read host configuration from environment variables."""
    host = os.environ.get("ENFORCEMENT_MCP_HOST", "")
    if not host:
        raise ValueError("ENFORCEMENT_MCP_HOST environment variable is required")
    return HostConfig(
        host=host,
        user=os.environ.get("ENFORCEMENT_MCP_USER", "root"),
        port=int(os.environ.get("ENFORCEMENT_MCP_PORT", "22")),
        key_file=os.environ.get("ENFORCEMENT_MCP_KEY_FILE"),
    )


def get_identity_config() -> IdentityConfig:
    """Read identity configuration from environment variables."""
    return IdentityConfig(
        mode=IdentityMode(os.environ.get("ENFORCEMENT_MCP_IDENTITY_MODE", "none")),
        authz_policy=AuthzPolicy(
            os.environ.get("ENFORCEMENT_MCP_AUTHZ_POLICY", "permissive")
        ),
        oauth_issuer=os.environ.get("ENFORCEMENT_MCP_OAUTH_ISSUER", ""),
        oauth_audience=os.environ.get("ENFORCEMENT_MCP_OAUTH_AUDIENCE", ""),
        oauth_jwks_uri=os.environ.get("ENFORCEMENT_MCP_OAUTH_JWKS_URI", ""),
        spiffe_trust_domain=os.environ.get("ENFORCEMENT_MCP_SPIFFE_TRUST_DOMAIN", ""),
        spiffe_socket=os.environ.get("ENFORCEMENT_MCP_SPIFFE_SOCKET", ""),
    )
