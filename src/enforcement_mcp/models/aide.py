"""Pydantic models for AIDE file integrity monitoring."""

from pydantic import BaseModel


class AIDEChange(BaseModel):
    """A single file change detected by AIDE."""

    path: str
    change_type: str  # "added", "removed", "changed"
    attributes: dict = {}  # permissions, size, mtime, checksum diffs


class AIDEReport(BaseModel):
    """Structured AIDE --check output."""

    added: int = 0
    removed: int = 0
    changed: int = 0
    total_files_checked: int = 0
    changes: list[AIDEChange] = []


class AIDEConfig(BaseModel):
    """Parsed AIDE configuration."""

    database_path: str = ""
    database_out_path: str = ""
    rules: list[dict] = []  # {"path": "/etc", "rule": "NORMAL"}
    custom_rules: list[dict] = []
