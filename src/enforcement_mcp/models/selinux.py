"""Pydantic models for SELinux data structures."""

from pydantic import BaseModel, computed_field


class SuggestedFix(BaseModel):
    """A suggested fix for an SELinux denial."""

    fix_type: str
    description: str
    command: str | None = None
    cil: str | None = None
    scope: str = "narrow"


class AvcDenial(BaseModel):
    """A parsed SELinux AVC denial."""

    source_type: str
    target_type: str
    tclass: str
    permission: str | list[str]
    permissions: list[str]
    pid: int | None = None
    comm: str | None = None
    timestamp: str = ""
    permissive: bool = False
    source_context: str | None = None
    target_context: str | None = None
    target_name: str | None = None
    path: str | None = None
    explanation: str | None = None
    suggested_fixes: list[SuggestedFix] | None = None


class PolicyRule(BaseModel):
    """A parsed SELinux policy rule."""

    source: str
    target: str
    tclass: str
    permissions: list[str]
    conditional: str | None = None
    conditional_state: bool | None = None


class BooleanInfo(BaseModel):
    """SELinux boolean with state."""

    name: str
    state: str
    description: str | None = None
    default_state: str | None = None


class FileContext(BaseModel):
    """Expected vs actual SELinux file context."""

    path: str
    expected_type: str | None = None
    actual_type: str | None = None
    expected_context: str | None = None
    actual_context: str | None = None
    fix_command: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def mismatch(self) -> bool:
        if self.expected_type is None or self.actual_type is None:
            return False
        return self.expected_type != self.actual_type


class TypeInfo(BaseModel):
    """SELinux type information."""

    name: str
    attributes: list[str] = []
    roles: list[str] = []
    transitions: list[dict] = []
    associated_booleans: list[str] = []


class SelinuxStatus(BaseModel):
    """SELinux subsystem status for host posture."""

    mode: str
    policy_type: str | None = None
    denial_count_24h: int = 0
    top_denied_types: list[str] = []
    custom_modules: list[str] = []
    booleans_non_default: list[str] = []
