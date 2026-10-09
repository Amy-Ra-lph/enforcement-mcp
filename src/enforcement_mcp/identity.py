"""Identity verification for agentic workloads.

Supports JWT (OAuth 2.0) and SPIFFE SVID verification.
When identity_mode is "none", all callers are anonymous.
When "permissive", identity is logged but not enforced.
When "strict", management tools require verified identity.
"""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.request
from datetime import UTC, datetime
from typing import Any

from .models.identity import CallerIdentity, IdentityMode, Role

logger = logging.getLogger(__name__)

_jwks_cache: dict[str, Any] | None = None
_jwks_fetched_at: float = 0
JWKS_CACHE_TTL = 3600


class IdentityVerificationError(Exception):
    pass


class TokenExpiredError(IdentityVerificationError):
    pass


class InvalidTokenError(IdentityVerificationError):
    pass


class JwksUnavailableError(IdentityVerificationError):
    pass


def _decode_base64url(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    import base64

    return base64.b64decode(s)


def _decode_jwt_unverified(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidTokenError("JWT must have 3 parts")
    header = json.loads(_decode_base64url(parts[0]))
    payload = json.loads(_decode_base64url(parts[1]))
    return header, payload


async def fetch_jwks(jwks_uri: str) -> dict:
    global _jwks_cache, _jwks_fetched_at
    now = datetime.now(UTC).timestamp()
    if _jwks_cache and (now - _jwks_fetched_at) < JWKS_CACHE_TTL:
        return _jwks_cache

    def _fetch() -> dict:
        req = urllib.request.Request(jwks_uri)  # noqa: S310
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            return json.loads(resp.read())

    _jwks_cache = await asyncio.to_thread(_fetch)
    _jwks_fetched_at = now
    return _jwks_cache


def _find_jwk(jwks: dict, kid: str | None) -> dict | None:
    keys = jwks.get("keys", [])
    if kid:
        for k in keys:
            if k.get("kid") == kid:
                return k
    if len(keys) == 1:
        return keys[0]
    return None


async def verify_jwt(
    token: str,
    *,
    jwks_uri: str,
    issuer: str,
    audience: str,
) -> CallerIdentity:
    try:
        import jwt as pyjwt
    except ImportError as e:
        raise IdentityVerificationError(
            "PyJWT not installed. Add 'pyjwt[crypto]' to dependencies."
        ) from e

    header, unverified = _decode_jwt_unverified(token)

    try:
        jwks_data = await fetch_jwks(jwks_uri)
    except Exception as e:
        raise JwksUnavailableError(f"Cannot fetch JWKS: {e}") from e

    kid = header.get("kid")
    jwk = _find_jwk(jwks_data, kid)
    if not jwk:
        raise InvalidTokenError(f"No matching JWK for kid={kid}")

    try:
        key = pyjwt.algorithms.RSAAlgorithm.from_jwk(jwk)
    except Exception:
        try:
            key = pyjwt.algorithms.ECAlgorithm.from_jwk(jwk)
        except Exception as e:
            raise InvalidTokenError(f"Unsupported key type in JWK: {e}") from e

    ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
    try:
        claims = pyjwt.decode(
            token,
            key,
            algorithms=ALLOWED_ALGORITHMS,
            issuer=issuer,
            audience=audience,
            options={"verify_exp": True},
        )
    except pyjwt.ExpiredSignatureError as e:
        raise TokenExpiredError("Token has expired") from e
    except pyjwt.InvalidTokenError as e:
        raise InvalidTokenError(f"Token validation failed: {e}") from e

    roles = _extract_roles(claims)
    return CallerIdentity(
        subject=claims.get("sub", "unknown"),
        issuer=claims.get("iss", issuer),
        roles=roles,
        token_claims=claims,
        verified=True,
    )


def _extract_roles(claims: dict) -> list[Role]:
    roles: list[Role] = []
    role_claim = claims.get("roles", [])
    if isinstance(role_claim, str):
        role_claim = [role_claim]
    realm_roles = claims.get("realm_access", {}).get("roles", [])
    all_roles = set(role_claim) | set(realm_roles)
    for r in all_roles:
        r_lower = r.lower().strip()
        if r_lower in ("admin", "administrator"):
            roles.append(Role.ADMIN)
        elif r_lower in ("operator", "ops"):
            roles.append(Role.OPERATOR)
        elif r_lower in ("viewer", "readonly", "read-only"):
            roles.append(Role.VIEWER)
        elif r_lower in ("containment", "incident"):
            roles.append(Role.CONTAINMENT)
    if not roles:
        roles.append(Role.VIEWER)
    return roles


def verify_spiffe_id(
    spiffe_id: str,
    trust_domain: str,
) -> CallerIdentity:
    if not spiffe_id.startswith("spiffe://"):
        raise InvalidTokenError("SPIFFE ID must start with spiffe://")

    parts = spiffe_id.replace("spiffe://", "").split("/", 1)
    domain = parts[0]
    if domain != trust_domain:
        raise InvalidTokenError(
            f"SPIFFE trust domain mismatch: got {domain}, expected {trust_domain}"
        )

    path = parts[1] if len(parts) > 1 else ""
    roles = _roles_from_spiffe_path(path)

    return CallerIdentity(
        subject=spiffe_id,
        issuer=f"spiffe://{trust_domain}",
        roles=roles,
        spiffe_id=spiffe_id,
        verified=True,
    )


def _roles_from_spiffe_path(path: str) -> list[Role]:
    segments = path.lower().split("/")
    if "admin" in segments:
        return [Role.ADMIN]
    if "operator" in segments or "ops" in segments:
        return [Role.OPERATOR]
    if "containment" in segments or "incident-response" in segments:
        return [Role.CONTAINMENT]
    return [Role.VIEWER]


def anonymous_identity() -> CallerIdentity:
    return CallerIdentity(
        subject="anonymous",
        issuer="local",
        roles=[Role.VIEWER],
        verified=False,
    )


async def verify_identity(
    token: str | None,
    *,
    mode: IdentityMode,
    oauth_issuer: str = "",
    oauth_audience: str = "",
    oauth_jwks_uri: str = "",
    spiffe_trust_domain: str = "",
) -> CallerIdentity:
    if mode == IdentityMode.NONE:
        return anonymous_identity()

    if not token:
        if mode == IdentityMode.BOTH or mode == IdentityMode.OAUTH or mode == IdentityMode.SPIFFE:
            return anonymous_identity()
        return anonymous_identity()

    if token.startswith("spiffe://"):
        if mode in (IdentityMode.SPIFFE, IdentityMode.BOTH):
            return verify_spiffe_id(token, spiffe_trust_domain)
        raise InvalidTokenError(f"SPIFFE identity not accepted in mode={mode.value}")

    if mode in (IdentityMode.OAUTH, IdentityMode.BOTH):
        return await verify_jwt(
            token,
            jwks_uri=oauth_jwks_uri,
            issuer=oauth_issuer,
            audience=oauth_audience,
        )

    raise InvalidTokenError(f"Cannot verify token in mode={mode.value}")
