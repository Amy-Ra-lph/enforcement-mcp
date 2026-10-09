"""Tests for MLS Pydantic models."""

from enforcement_mcp.models.mls import MlsCategory, MlsFileLevel, MlsUserMapping


class TestMlsUserMapping:
    def test_basic(self):
        m = MlsUserMapping(login="jsmith", selinux_user="staff_u", range="s0-s0:c0.c1023")
        assert m.login == "jsmith"


class TestMlsFileLevel:
    def test_basic(self):
        f = MlsFileLevel(
            target="/etc/shadow",
            level="s0",
            user="system_u",
            role="object_r",
            type="shadow_t",
        )
        assert f.type == "shadow_t"


class TestMlsCategory:
    def test_with_translation(self):
        c = MlsCategory(category="c0", translation="CompanyConfidential")
        assert c.translation == "CompanyConfidential"

    def test_without_translation(self):
        c = MlsCategory(category="c5")
        assert c.translation is None
