"""Tests for authorization policy."""

from enforcement_mcp.authz import TOOL_PERMISSIONS, check_authorization
from enforcement_mcp.models.identity import AuthzPolicy, CallerIdentity, Role


def _make_identity(
    roles: list[Role],
    verified: bool = True,
    subject: str = "test-agent",
) -> CallerIdentity:
    return CallerIdentity(
        subject=subject,
        issuer="test",
        roles=roles,
        verified=verified,
    )


class TestPermissiveMode:
    def test_any_role_allowed(self):
        identity = _make_identity([Role.VIEWER])
        result = check_authorization(identity, "manage.set_boolean", AuthzPolicy.PERMISSIVE)
        assert result["authorized"]
        assert not result["enforced"]

    def test_would_deny_flagged(self):
        identity = _make_identity([Role.VIEWER])
        result = check_authorization(identity, "manage.set_boolean", AuthzPolicy.PERMISSIVE)
        assert result["would_deny"]

    def test_would_not_deny_with_correct_role(self):
        identity = _make_identity([Role.OPERATOR])
        result = check_authorization(identity, "manage.set_boolean", AuthzPolicy.PERMISSIVE)
        assert not result["would_deny"]

    def test_unverified_allowed_in_permissive(self):
        identity = _make_identity([Role.ADMIN], verified=False)
        result = check_authorization(identity, "manage.load_module", AuthzPolicy.PERMISSIVE)
        assert result["authorized"]


class TestStrictMode:
    def test_admin_can_manage(self):
        identity = _make_identity([Role.ADMIN])
        result = check_authorization(identity, "manage.set_boolean", AuthzPolicy.STRICT)
        assert result["authorized"]
        assert result["enforced"]

    def test_operator_can_manage_selinux(self):
        identity = _make_identity([Role.OPERATOR])
        result = check_authorization(identity, "manage.set_boolean", AuthzPolicy.STRICT)
        assert result["authorized"]

    def test_viewer_cannot_manage(self):
        identity = _make_identity([Role.VIEWER])
        result = check_authorization(identity, "manage.set_boolean", AuthzPolicy.STRICT)
        assert not result["authorized"]
        assert "lacks required role" in result["reason"]

    def test_viewer_can_diagnose(self):
        identity = _make_identity([Role.VIEWER])
        result = check_authorization(identity, "diagnosis.troubleshoot", AuthzPolicy.STRICT)
        assert result["authorized"]

    def test_containment_can_contain(self):
        identity = _make_identity([Role.CONTAINMENT])
        result = check_authorization(identity, "manage.cve_contain", AuthzPolicy.STRICT)
        assert result["authorized"]

    def test_containment_cannot_set_boolean(self):
        identity = _make_identity([Role.CONTAINMENT])
        result = check_authorization(identity, "manage.set_boolean", AuthzPolicy.STRICT)
        assert not result["authorized"]

    def test_unverified_blocked_for_manage(self):
        identity = _make_identity([Role.ADMIN], verified=False)
        result = check_authorization(identity, "manage.load_module", AuthzPolicy.STRICT)
        assert not result["authorized"]
        assert "verified identity" in result["reason"]

    def test_unverified_allowed_for_diagnosis(self):
        identity = _make_identity([Role.VIEWER], verified=False)
        result = check_authorization(identity, "diagnosis.host_posture", AuthzPolicy.STRICT)
        assert result["authorized"]

    def test_mls_admin_only(self):
        identity = _make_identity([Role.OPERATOR])
        result = check_authorization(identity, "manage.mls_assign_category", AuthzPolicy.STRICT)
        assert not result["authorized"]

    def test_mls_admin_allowed(self):
        identity = _make_identity([Role.ADMIN])
        result = check_authorization(identity, "manage.mls_assign_category", AuthzPolicy.STRICT)
        assert result["authorized"]


class TestToolPermissionsCoverage:
    def test_all_tools_have_permissions(self):
        expected_tools = [
            "diagnosis.troubleshoot",
            "diagnosis.host_posture",
            "diagnosis.avc_denials",
            "manage.assess_risk",
            "manage.set_boolean",
            "manage.cve_contain",
            "manage.containment_expire",
            "manage.mls_set_user_range",
        ]
        for tool in expected_tools:
            assert tool in TOOL_PERMISSIONS, f"Missing permissions for {tool}"

    def test_diagnosis_tools_allow_all_roles(self):
        for tool, roles in TOOL_PERMISSIONS.items():
            if tool.startswith("diagnosis."):
                assert Role.VIEWER in roles, f"{tool} should allow VIEWER"

    def test_manage_tools_exclude_viewer(self):
        manage_tools = [t for t in TOOL_PERMISSIONS if t.startswith("manage.")]
        viewer_only = [t for t in manage_tools if Role.VIEWER in TOOL_PERMISSIONS[t]]
        assert viewer_only == [], f"VIEWER should not access: {viewer_only}"
