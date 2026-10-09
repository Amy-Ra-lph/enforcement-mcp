"""Identity and authorization models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class IdentityMode(StrEnum):
    NONE = "none"
    OAUTH = "oauth"
    SPIFFE = "spiffe"
    BOTH = "both"


class AuthzPolicy(StrEnum):
    PERMISSIVE = "permissive"
    STRICT = "strict"


class Role(StrEnum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    CONTAINMENT = "containment"


class CallerIdentity(BaseModel):
    subject: str
    issuer: str
    roles: list[Role] = []
    spiffe_id: str | None = None
    token_claims: dict | None = None
    verified: bool = False

    @property
    def display_name(self) -> str:
        if self.spiffe_id:
            return self.spiffe_id
        return self.subject


class AuditEntry(BaseModel):
    timestamp: str
    caller: str
    tool: str
    parameters: dict
    risk_score: int | None = None
    risk_level: str | None = None
    result_status: str
    identity_mode: str
    authz_decision: str
