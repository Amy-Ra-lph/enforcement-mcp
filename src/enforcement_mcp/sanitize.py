"""Input sanitization for shell command arguments.

Every tool parameter that flows into an SSH command MUST pass through
one of these validators first. Returns the sanitized value or raises
ValueError with a structured error message.
"""

from __future__ import annotations

import re
import shlex

IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.-]*$")
SELINUX_TYPE_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
MLS_RANGE_RE = re.compile(r"^s\d+(-s\d+)?(:[cC]\d+([.,][cC]?\d+)*)?$")
MLS_CATEGORY_RE = re.compile(r"^[cC]\d+$")
PROCESS_NAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]+$")
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
PATH_FORBIDDEN = re.compile(r"[;|&`$(){}!<>\n\r\\]")
SELINUX_CONTEXT_PATH_RE = re.compile(r"^/[a-zA-Z0-9_./\-()*?]+$")


class SanitizationError(ValueError):
    def __init__(self, param: str, value: str, reason: str) -> None:
        self.param = param
        self.value_preview = value[:50] if len(value) > 50 else value
        self.reason = reason
        super().__init__(f"Invalid {param}: {reason}")

    def to_dict(self) -> dict:
        return {
            "error": "invalid_input",
            "parameter": self.param,
            "reason": self.reason,
        }


def sanitize_path(path: str, param_name: str = "path") -> str:
    if not path or not path.startswith("/"):
        raise SanitizationError(param_name, path, "Must be an absolute path")
    if PATH_FORBIDDEN.search(path):
        raise SanitizationError(param_name, path, "Contains forbidden characters")
    if ".." in path:
        raise SanitizationError(param_name, path, "Path traversal not allowed")
    return path


def sanitize_identifier(name: str, param_name: str = "name") -> str:
    if not name:
        raise SanitizationError(param_name, "", "Must not be empty")
    if not IDENTIFIER_RE.match(name):
        raise SanitizationError(
            param_name,
            name,
            "Must match [a-zA-Z_][a-zA-Z0-9_.-]* (letters, digits, underscore, hyphen, dot)",
        )
    if len(name) > 200:
        raise SanitizationError(param_name, name, "Too long (max 200 chars)")
    return name


def sanitize_selinux_type(type_name: str, param_name: str = "type") -> str:
    if not type_name:
        raise SanitizationError(param_name, "", "Must not be empty")
    if not SELINUX_TYPE_RE.match(type_name):
        raise SanitizationError(
            param_name, type_name, "Must match SELinux type pattern [a-zA-Z_][a-zA-Z0-9_]*"
        )
    return type_name


def sanitize_selinux_permission(perm: str, param_name: str = "permission") -> str:
    if not perm:
        raise SanitizationError(param_name, "", "Must not be empty")
    if not SELINUX_TYPE_RE.match(perm):
        raise SanitizationError(
            param_name, perm, "Must match SELinux permission pattern [a-zA-Z_][a-zA-Z0-9_]*"
        )
    return perm


def sanitize_selinux_class(tclass: str, param_name: str = "tclass") -> str:
    return sanitize_selinux_type(tclass, param_name)


def sanitize_context_path(path: str, param_name: str = "path") -> str:
    if not path:
        raise SanitizationError(param_name, "", "Must not be empty")
    if not SELINUX_CONTEXT_PATH_RE.match(path):
        raise SanitizationError(
            param_name,
            path,
            "Must be a valid file context path pattern (absolute, no shell metacharacters)",
        )
    return path


def sanitize_mls_range(range_spec: str, param_name: str = "range_spec") -> str:
    if not range_spec:
        raise SanitizationError(param_name, "", "Must not be empty")
    if not MLS_RANGE_RE.match(range_spec):
        raise SanitizationError(
            param_name,
            range_spec,
            "Must match MLS range format (e.g., 's0', 's0-s0:c0.c1023', 's0:c5,c10')",
        )
    return range_spec


def sanitize_mls_categories(categories: list[str]) -> list[str]:
    validated = []
    for cat in categories:
        if not MLS_CATEGORY_RE.match(cat):
            raise SanitizationError(
                "categories", cat, "Each category must match c[0-9]+ (e.g., 'c5', 'c10')"
            )
        validated.append(cat)
    return validated


def sanitize_process_name(process: str, param_name: str = "process") -> str:
    if not process:
        raise SanitizationError(param_name, "", "Must not be empty")
    if not PROCESS_NAME_RE.match(process):
        raise SanitizationError(
            param_name, process, "Must contain only letters, digits, hyphens, underscores, dots"
        )
    return process


def sanitize_login(login: str, param_name: str = "login") -> str:
    if not login:
        raise SanitizationError(param_name, "", "Must not be empty")
    if not IDENTIFIER_RE.match(login):
        raise SanitizationError(
            param_name, login, "Must be a valid login name (alphanumeric, underscore, hyphen, dot)"
        )
    return login


def sanitize_cil(cil: str, param_name: str = "cil") -> str:
    if not cil:
        raise SanitizationError(param_name, "", "Must not be empty")
    if "EMCP_EOF" in cil:
        raise SanitizationError(param_name, cil, "CIL content contains reserved delimiter")
    forbidden_shell = re.compile(r"[`$]")
    for i, line in enumerate(cil.split("\n")):
        stripped = line.strip()
        if not stripped or stripped[0] in ("(", ")", ";"):
            continue
        if forbidden_shell.search(stripped):
            raise SanitizationError(
                param_name,
                stripped,
                f"Line {i + 1} contains shell metacharacters outside CIL syntax",
            )
    return cil


def quote_arg(value: str) -> str:
    return shlex.quote(value)
