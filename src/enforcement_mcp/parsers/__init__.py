"""CLI output parsers for SELinux, fapolicyd, AIDE, and audit tools."""

from ._hardening import InputTooLargeError, sanitize_parsed_path, validate_input_size
from .ausearch import parse_avc_denials, parse_fanotify_denials
from .fapolicyd_cli import parse_fapolicyd_dumpdb, parse_fapolicyd_list, parse_fapolicyd_rules
from .selinux_cli import (
    parse_getenforce,
    parse_getsebool,
    parse_matchpathcon,
    parse_semanage_login,
    parse_sesearch_allow,
)
from .time_utils import parse_time_spec

__all__ = [
    "InputTooLargeError",
    "parse_avc_denials",
    "parse_fanotify_denials",
    "parse_fapolicyd_dumpdb",
    "parse_fapolicyd_list",
    "parse_fapolicyd_rules",
    "parse_getenforce",
    "parse_getsebool",
    "parse_matchpathcon",
    "parse_semanage_login",
    "parse_sesearch_allow",
    "parse_time_spec",
    "sanitize_parsed_path",
    "validate_input_size",
]
