"""Pydantic models for CVE data and containment tracking."""

from pydantic import BaseModel


class CveDetail(BaseModel):
    """CVE metadata from Red Hat Security Data API."""

    cve_id: str
    severity: str = "unknown"
    cvss3_score: float | None = None
    description: str = ""
    affected_packages: list[str] = []
    fixed_in: list[str] = []
    cwe: str | None = None
    public_date: str | None = None


class ExploitStep(BaseModel):
    """One step in a CVE exploit chain mapped to SELinux permissions."""

    step: int
    technique: str
    technique_id: str
    description: str
    required_permissions: list[dict]
    blocked: bool
    blocking_rule: str | None = None


class CveExposure(BaseModel):
    """Assessment of current policy effectiveness against a CVE."""

    cve: CveDetail
    exploit_chain: list[ExploitStep]
    containment_score: int
    residual_risk: str
    total_steps: int
    blocked_steps: int


class Containment(BaseModel):
    """A tracked CVE containment applied to the system."""

    cve_id: str
    module_name: str
    date_applied: str
    strategy: str
    cil_content: str
    patched_rpm_available: bool = False
    safe_to_remove: bool = False


class ContainmentOption(BaseModel):
    """A proposed containment option for a CVE."""

    strategy: str
    description: str
    cil_content: str
    module_name: str
    effectiveness: int
    operational_impact: str
    risk_score: int
