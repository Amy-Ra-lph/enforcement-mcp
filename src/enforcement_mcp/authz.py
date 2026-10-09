"""Authorization policy for tool access control.

Maps roles to tool permissions. Two modes:
- permissive: identity logged, not enforced (any role can call any tool)
- strict: management tools require appropriate role
"""

from __future__ import annotations

from .models.identity import AuthzPolicy, CallerIdentity, Role

TOOL_PERMISSIONS: dict[str, set[Role]] = {
    "diagnosis.troubleshoot": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.host_posture": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.avc_denials": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.policy_query": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.boolean_list": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.file_context": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.denial_explain": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.fapolicyd_status": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.fapolicyd_denials": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.fapolicyd_trust_check": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.fapolicyd_rules": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.mls_user_mappings": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.mls_file_level": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.mls_categories": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.cve_exposure": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "diagnosis.active_containments": {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT},
    "manage.assess_risk": {Role.ADMIN, Role.OPERATOR, Role.CONTAINMENT},
    "manage.set_boolean": {Role.ADMIN, Role.OPERATOR},
    "manage.generate_module": {Role.ADMIN, Role.OPERATOR},
    "manage.load_module": {Role.ADMIN, Role.OPERATOR},
    "manage.remove_module": {Role.ADMIN, Role.OPERATOR},
    "manage.set_file_context": {Role.ADMIN, Role.OPERATOR},
    "manage.fapolicyd_trust_add": {Role.ADMIN, Role.OPERATOR},
    "manage.fapolicyd_trust_remove": {Role.ADMIN, Role.OPERATOR},
    "manage.mls_assign_category": {Role.ADMIN},
    "manage.mls_set_user_range": {Role.ADMIN},
    "manage.cve_contain": {Role.ADMIN, Role.OPERATOR, Role.CONTAINMENT},
    "manage.containment_expire": {Role.ADMIN, Role.OPERATOR, Role.CONTAINMENT},
}

ALL_ROLES = {Role.ADMIN, Role.OPERATOR, Role.VIEWER, Role.CONTAINMENT}


def check_authorization(
    identity: CallerIdentity,
    tool_name: str,
    policy: AuthzPolicy,
) -> dict:
    allowed_roles = TOOL_PERMISSIONS.get(tool_name, ALL_ROLES)
    caller_roles = set(identity.roles)
    has_permission = bool(caller_roles & allowed_roles)

    if policy == AuthzPolicy.PERMISSIVE:
        return {
            "authorized": True,
            "enforced": False,
            "caller": identity.display_name,
            "roles": [r.value for r in identity.roles],
            "would_deny": not has_permission,
        }

    if not identity.verified and tool_name.startswith("manage."):
        return {
            "authorized": False,
            "enforced": True,
            "caller": identity.display_name,
            "reason": "Management tools require verified identity in strict mode",
        }

    if not has_permission:
        return {
            "authorized": False,
            "enforced": True,
            "caller": identity.display_name,
            "roles": [r.value for r in identity.roles],
            "required_roles": [r.value for r in allowed_roles],
            "reason": f"Caller lacks required role for {tool_name}",
        }

    return {
        "authorized": True,
        "enforced": True,
        "caller": identity.display_name,
        "roles": [r.value for r in identity.roles],
    }
