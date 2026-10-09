"""Tests for identity verification."""

import base64
import json

import pytest

from enforcement_mcp.identity import (
    InvalidTokenError,
    _decode_base64url,
    _decode_jwt_unverified,
    _extract_roles,
    _roles_from_spiffe_path,
    anonymous_identity,
    verify_identity,
    verify_spiffe_id,
)
from enforcement_mcp.models.identity import IdentityMode, Role


def _b64url(data: dict) -> str:
    raw = json.dumps(data).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_jwt(header: dict, payload: dict) -> str:
    return f"{_b64url(header)}.{_b64url(payload)}.fakesignature"


class TestBase64Decode:
    def test_standard_padding(self):
        original = b"hello world"
        encoded = base64.urlsafe_b64encode(original).rstrip(b"=").decode()
        assert _decode_base64url(encoded) == original

    def test_no_padding_needed(self):
        original = b"abcd"
        encoded = base64.urlsafe_b64encode(original).rstrip(b"=").decode()
        assert _decode_base64url(encoded) == original


class TestDecodeJwtUnverified:
    def test_valid_jwt(self):
        header = {"alg": "RS256", "typ": "JWT", "kid": "key1"}
        payload = {"sub": "agent-1", "iss": "https://idp.example.com", "exp": 9999999999}
        token = _make_jwt(header, payload)
        h, p = _decode_jwt_unverified(token)
        assert h["alg"] == "RS256"
        assert p["sub"] == "agent-1"

    def test_invalid_parts(self):
        with pytest.raises(InvalidTokenError, match="3 parts"):
            _decode_jwt_unverified("only.two")

    def test_four_parts(self):
        with pytest.raises(InvalidTokenError, match="3 parts"):
            _decode_jwt_unverified("one.two.three.four")


class TestExtractRoles:
    def test_admin_role(self):
        roles = _extract_roles({"roles": ["admin"]})
        assert Role.ADMIN in roles

    def test_administrator_alias(self):
        roles = _extract_roles({"roles": ["Administrator"]})
        assert Role.ADMIN in roles

    def test_operator_role(self):
        roles = _extract_roles({"roles": ["operator"]})
        assert Role.OPERATOR in roles

    def test_ops_alias(self):
        roles = _extract_roles({"roles": ["ops"]})
        assert Role.OPERATOR in roles

    def test_viewer_role(self):
        roles = _extract_roles({"roles": ["viewer"]})
        assert Role.VIEWER in roles

    def test_readonly_alias(self):
        roles = _extract_roles({"roles": ["readonly"]})
        assert Role.VIEWER in roles

    def test_containment_role(self):
        roles = _extract_roles({"roles": ["containment"]})
        assert Role.CONTAINMENT in roles

    def test_incident_alias(self):
        roles = _extract_roles({"roles": ["incident"]})
        assert Role.CONTAINMENT in roles

    def test_keycloak_realm_access(self):
        roles = _extract_roles({"realm_access": {"roles": ["admin"]}})
        assert Role.ADMIN in roles

    def test_default_viewer_when_unknown(self):
        roles = _extract_roles({"roles": ["custom_role"]})
        assert roles == [Role.VIEWER]

    def test_no_roles_claim(self):
        roles = _extract_roles({})
        assert roles == [Role.VIEWER]

    def test_string_role(self):
        roles = _extract_roles({"roles": "admin"})
        assert Role.ADMIN in roles


class TestSpiffeVerification:
    def test_valid_spiffe_id(self):
        identity = verify_spiffe_id(
            "spiffe://example.com/workload/agent-1",
            trust_domain="example.com",
        )
        assert identity.verified
        assert identity.spiffe_id == "spiffe://example.com/workload/agent-1"
        assert identity.subject == "spiffe://example.com/workload/agent-1"

    def test_trust_domain_mismatch(self):
        with pytest.raises(InvalidTokenError, match="mismatch"):
            verify_spiffe_id(
                "spiffe://evil.com/workload/agent-1",
                trust_domain="example.com",
            )

    def test_invalid_prefix(self):
        with pytest.raises(InvalidTokenError, match="spiffe://"):
            verify_spiffe_id(
                "https://example.com/workload/agent-1",
                trust_domain="example.com",
            )

    def test_admin_path(self):
        identity = verify_spiffe_id(
            "spiffe://example.com/admin/policy-manager",
            trust_domain="example.com",
        )
        assert Role.ADMIN in identity.roles

    def test_operator_path(self):
        identity = verify_spiffe_id(
            "spiffe://example.com/operator/sre-agent",
            trust_domain="example.com",
        )
        assert Role.OPERATOR in identity.roles

    def test_containment_path(self):
        identity = verify_spiffe_id(
            "spiffe://example.com/incident-response/cve-handler",
            trust_domain="example.com",
        )
        assert Role.CONTAINMENT in identity.roles

    def test_default_viewer_path(self):
        identity = verify_spiffe_id(
            "spiffe://example.com/workload/scanner",
            trust_domain="example.com",
        )
        assert Role.VIEWER in identity.roles

    def test_domain_only(self):
        identity = verify_spiffe_id(
            "spiffe://example.com",
            trust_domain="example.com",
        )
        assert identity.verified


class TestRolesFromSpiffePath:
    def test_admin(self):
        assert Role.ADMIN in _roles_from_spiffe_path("admin/tool")

    def test_ops(self):
        assert Role.OPERATOR in _roles_from_spiffe_path("ops/agent")

    def test_incident(self):
        assert Role.CONTAINMENT in _roles_from_spiffe_path("incident-response/handler")

    def test_generic(self):
        assert Role.VIEWER in _roles_from_spiffe_path("workload/scanner")


class TestAnonymousIdentity:
    def test_anonymous_has_viewer(self):
        identity = anonymous_identity()
        assert not identity.verified
        assert Role.VIEWER in identity.roles
        assert Role.ADMIN not in identity.roles
        assert identity.subject == "anonymous"


class TestVerifyIdentity:
    @pytest.mark.asyncio
    async def test_none_mode_returns_anonymous(self):
        identity = await verify_identity(
            token="some-token",
            mode=IdentityMode.NONE,
        )
        assert not identity.verified
        assert identity.subject == "anonymous"

    @pytest.mark.asyncio
    async def test_no_token_returns_anonymous(self):
        identity = await verify_identity(
            token=None,
            mode=IdentityMode.OAUTH,
        )
        assert not identity.verified

    @pytest.mark.asyncio
    async def test_spiffe_token_in_spiffe_mode(self):
        identity = await verify_identity(
            token="spiffe://example.com/operator/agent",
            mode=IdentityMode.SPIFFE,
            spiffe_trust_domain="example.com",
        )
        assert identity.verified
        assert Role.OPERATOR in identity.roles

    @pytest.mark.asyncio
    async def test_spiffe_token_in_both_mode(self):
        identity = await verify_identity(
            token="spiffe://example.com/admin/mgr",
            mode=IdentityMode.BOTH,
            spiffe_trust_domain="example.com",
        )
        assert identity.verified

    @pytest.mark.asyncio
    async def test_spiffe_token_rejected_in_oauth_mode(self):
        with pytest.raises(InvalidTokenError, match="not accepted"):
            await verify_identity(
                token="spiffe://example.com/admin/mgr",
                mode=IdentityMode.OAUTH,
            )

    @pytest.mark.asyncio
    async def test_empty_string_token_returns_anonymous(self):
        identity = await verify_identity(
            token="",
            mode=IdentityMode.OAUTH,
        )
        assert not identity.verified
