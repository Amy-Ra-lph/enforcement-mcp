"""Pydantic models for risk assessment."""

from pydantic import BaseModel


class RiskAssessment(BaseModel):
    """Pre-change risk assessment result."""

    risk_score: int
    risk_level: str
    blast_radius: dict
    attack_surface_delta: dict
    reversibility: dict
    least_privilege_alternatives: list[dict]
    recommendation: str
    factors: list[dict]
