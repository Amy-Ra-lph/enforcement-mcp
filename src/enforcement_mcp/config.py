"""Configuration for enforcement-mcp."""

import os

from pydantic import BaseModel


class HostConfig(BaseModel):
    """SSH target host configuration."""

    host: str
    user: str = "root"
    port: int = 22
    key_file: str | None = None


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
