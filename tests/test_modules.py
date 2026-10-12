"""Tests for the modular architecture — registration and discovery."""

import pytest

from enforcement_mcp.modules import discover_modules, get_module


class TestModuleDiscovery:
    def test_discover_returns_all_modules(self):
        modules = discover_modules()
        assert "selinux" in modules
        assert "fapolicyd" in modules
        assert "mls" in modules
        assert "aide" in modules

    def test_get_module_selinux(self):
        mod = get_module("selinux")
        assert hasattr(mod, "register_readonly_tools")
        assert hasattr(mod, "register_management_tools")
        assert hasattr(mod, "register_all")

    def test_get_module_fapolicyd(self):
        mod = get_module("fapolicyd")
        assert hasattr(mod, "register_readonly_tools")
        assert hasattr(mod, "register_all")

    def test_get_module_mls(self):
        mod = get_module("mls")
        assert hasattr(mod, "register_readonly_tools")
        assert hasattr(mod, "register_all")

    def test_get_module_aide(self):
        mod = get_module("aide")
        assert hasattr(mod, "register_readonly_tools")
        assert hasattr(mod, "register_management_tools")
        assert hasattr(mod, "register_all")

    def test_get_module_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown module"):
            get_module("nonexistent")
