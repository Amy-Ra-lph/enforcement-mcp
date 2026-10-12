# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""Configuration extensions for SPIFFE/WID and remediation.

These additions go into linux-mcp's config.py. They're kept here as a
reference for the PR diff rather than as importable code.

Changes to existing linux-mcp files:

1. config.py — AuthProvider enum:
    class AuthProvider(StrEnum):
        GOOGLE = "google"
        GITHUB = "github"
        JWT = "jwt"
        INTROSPECTION = "introspection"
        SPIFFE = "spiffe"              # ← ADD

2. config.py — New config class:
    class SPIFFEAuthConfig(BaseSettings):
        trust_domain: str
        workload_api_socket: str | None = None
        require_svid: bool = False

3. config.py — AuthConfig class:
    class AuthConfig(BaseSettings):
        provider: AuthProvider | None = None
        google: GoogleAuthConfig | None = None
        github: GitHubAuthConfig | None = None
        jwt: JWTAuthConfig | None = None
        introspection: IntrospectionAuthConfig | None = None
        spiffe: SPIFFEAuthConfig | None = None   # ← ADD

4. auth.py — create_auth_provider():
    elif CONFIG.auth.provider == AuthProvider.SPIFFE:
        if CONFIG.auth.spiffe is None:
            raise ValueError(
                "SPIFFE auth provider selected but "
                "LINUX_MCP_AUTH__SPIFFE__* not configured"
            )
        from .auth_spiffe import create_spiffe_provider
        return create_spiffe_provider(CONFIG.auth.spiffe, base_url)

5. commands.py — New command for sesearch boolean lookup:
    CommandSpec(
        name="selinux_sesearch_boolean",
        command="sesearch --allow -s {source} -t {target} -c {tclass} -p {permission} -b 2>/dev/null",
        required_packages=["setools-console"],
    )

Environment variables (following linux-mcp's existing pattern):
    LINUX_MCP_AUTH__PROVIDER=spiffe
    LINUX_MCP_AUTH__SPIFFE__TRUST_DOMAIN=example.com
    LINUX_MCP_AUTH__SPIFFE__WORKLOAD_API_SOCKET=/run/spire/sockets/agent.sock
    LINUX_MCP_AUTH__SPIFFE__REQUIRE_SVID=false
"""
