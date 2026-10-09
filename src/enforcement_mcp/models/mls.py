"""Pydantic models for MLS data structures."""

from pydantic import BaseModel


class MlsUserMapping(BaseModel):
    """MLS user-to-SELinux-user mapping."""

    login: str
    selinux_user: str
    range: str


class MlsFileLevel(BaseModel):
    """MLS level of a file or process."""

    target: str
    level: str = ""
    categories: list[str] = []
    user: str = ""
    role: str = ""
    type: str = ""


class MlsCategory(BaseModel):
    """MLS category definition."""

    category: str
    translation: str | None = None
