"""Tests for SELinux Pydantic models."""

from enforcement_mcp.models.selinux import (
    AvcDenial,
    BooleanInfo,
    FileContext,
    PolicyRule,
    SuggestedFix,
)


class TestAvcDenial:
    def test_create(self):
        denial = AvcDenial(
            source_type="httpd_t",
            target_type="user_home_t",
            tclass="file",
            permission="read",
            permissions=["read"],
            pid=4821,
            comm="httpd",
            permissive=False,
        )
        assert denial.source_type == "httpd_t"
        assert denial.tclass == "file"

    def test_serializes(self):
        denial = AvcDenial(
            source_type="httpd_t",
            target_type="user_home_t",
            tclass="file",
            permission="read",
            permissions=["read"],
        )
        data = denial.model_dump()
        assert data["source_type"] == "httpd_t"
        assert isinstance(data["permissions"], list)


class TestPolicyRule:
    def test_unconditional(self):
        rule = PolicyRule(
            source="httpd_t",
            target="httpd_sys_content_t",
            tclass="file",
            permissions=["read", "open"],
        )
        assert rule.conditional is None

    def test_conditional(self):
        rule = PolicyRule(
            source="httpd_t",
            target="user_home_dir_t",
            tclass="dir",
            permissions=["read"],
            conditional="httpd_enable_homedirs",
            conditional_state=True,
        )
        assert rule.conditional == "httpd_enable_homedirs"


class TestFileContext:
    def test_mismatch(self):
        fc = FileContext(
            path="/home/jsmith/public_html",
            expected_type="httpd_sys_content_t",
            actual_type="user_home_dir_t",
        )
        assert fc.mismatch is True

    def test_match(self):
        fc = FileContext(
            path="/var/www/html",
            expected_type="httpd_sys_content_t",
            actual_type="httpd_sys_content_t",
        )
        assert fc.mismatch is False

    def test_none_types(self):
        fc = FileContext(path="/whatever")
        assert fc.mismatch is False


class TestBooleanInfo:
    def test_basic(self):
        b = BooleanInfo(name="httpd_enable_homedirs", state="off")
        assert b.state == "off"


class TestSuggestedFix:
    def test_boolean_fix(self):
        fix = SuggestedFix(
            fix_type="boolean",
            description="Enable httpd home directory access",
            command="setsebool -P httpd_enable_homedirs on",
            scope="broad",
        )
        assert fix.fix_type == "boolean"
