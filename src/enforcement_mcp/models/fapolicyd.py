"""Pydantic models for fapolicyd data structures."""

from pydantic import BaseModel


class FapolicydDenial(BaseModel):
    """A parsed fapolicyd FANOTIFY denial."""

    timestamp: str = ""
    path: str | None = None
    pid: int | None = None
    uid: int | None = None
    exe: str | None = None
    decision: str = "deny"
    obj_trust: int | None = None
    subject_context: str | None = None
    response: int | None = None


class FapolicydStatus(BaseModel):
    """fapolicyd daemon status."""

    active: bool
    rules: int = 0
    trust_db_entries: int = 0
    integrity_check: str | None = None
    permissive: bool = False


class TrustEntry(BaseModel):
    """A fapolicyd trust database entry."""

    path: str
    size: str | None = None
    sha256: str | None = None
    trusted: bool = False
    reason: str | None = None
    source: str | None = None


class FapolicydRule(BaseModel):
    """A parsed fapolicyd rule."""

    number: int | None = None
    decision: str | None = None
    raw: str = ""
