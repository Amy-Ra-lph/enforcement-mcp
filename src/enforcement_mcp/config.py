"""Configuration for enforcement-mcp."""

import os

from pydantic import BaseModel

from .models.identity import AuthzPolicy, IdentityMode
from .sanitize import sanitize_hostname, sanitize_username


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


def parse_target_string(target: str) -> HostConfig:
    """Parse 'user@host:port' into HostConfig.

    Supports: hostname, user@hostname, hostname:port, user@hostname:port.
    SSH user/port/key_file fall back to env vars for unspecified parts.
    """
    user = os.environ.get("ENFORCEMENT_MCP_USER", "root")
    port = int(os.environ.get("ENFORCEMENT_MCP_PORT", "22"))
    key_file = os.environ.get("ENFORCEMENT_MCP_KEY_FILE")

    host = target
    if "@" in target:
        user, host = target.rsplit("@", 1)
        sanitize_username(user)
    if ":" in host:
        host, port_str = host.rsplit(":", 1)
        port = int(port_str)
    sanitize_hostname(host)

    return HostConfig(host=host, user=user, port=port, key_file=key_file)


def get_host_config(target: str | None = None) -> HostConfig:
    """Resolve host configuration.

    Priority: explicit target > ENFORCEMENT_MCP_TARGET env > ENFORCEMENT_MCP_HOST env.
    """
    if target:
        return parse_target_string(target)

    host = os.environ.get("ENFORCEMENT_MCP_TARGET") or os.environ.get("ENFORCEMENT_MCP_HOST", "")
    if not host:
        raise ValueError(
            "No target specified. Pass a target parameter on the tool call, "
            "use --target on the serve command, or set ENFORCEMENT_MCP_TARGET."
        )
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
        authz_policy=AuthzPolicy(os.environ.get("ENFORCEMENT_MCP_AUTHZ_POLICY", "permissive")),
        oauth_issuer=os.environ.get("ENFORCEMENT_MCP_OAUTH_ISSUER", ""),
        oauth_audience=os.environ.get("ENFORCEMENT_MCP_OAUTH_AUDIENCE", ""),
        oauth_jwks_uri=os.environ.get("ENFORCEMENT_MCP_OAUTH_JWKS_URI", ""),
        spiffe_trust_domain=os.environ.get("ENFORCEMENT_MCP_SPIFFE_TRUST_DOMAIN", ""),
        spiffe_socket=os.environ.get("ENFORCEMENT_MCP_SPIFFE_SOCKET", ""),
    )
