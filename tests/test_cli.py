"""Tests for CLI setup and check commands."""

import pytest

from enforcement_mcp.cli import _merge_flat, _merge_nested, cmd_setup


class TestMergeFlat:
    def test_empty_config_write(self):
        config = {}
        snippet = {"command": "uvx", "args": ["enforcement-mcp"]}
        _merge_flat(config, snippet, write=True)
        assert "enforcement-mcp" in config
        assert config["enforcement-mcp"]["command"] == "uvx"

    def test_existing_entry_detected(self):
        config = {"enforcement-mcp": {"command": "old"}}
        snippet = {"command": "new"}
        result = _merge_flat(config, snippet)
        assert result == "enforcement-mcp"

    def test_no_existing_entry(self):
        config = {"other-mcp": {"command": "x"}}
        snippet = {"command": "uvx"}
        result = _merge_flat(config, snippet)
        assert result is None


class TestMergeNested:
    def test_empty_config_write(self):
        config = {}
        snippet = {"command": "uvx"}
        _merge_nested(config, snippet, write=True)
        assert config["mcpServers"]["enforcement-mcp"]["command"] == "uvx"

    def test_existing_entry_detected(self):
        config = {"mcpServers": {"enforcement-mcp": {"command": "old"}}}
        snippet = {"command": "new"}
        result = _merge_nested(config, snippet)
        assert result == "mcpServers.enforcement-mcp"

    def test_preserves_other_servers(self):
        config = {"mcpServers": {"other-mcp": {"command": "x"}}}
        snippet = {"command": "uvx"}
        _merge_nested(config, snippet, write=True)
        assert "other-mcp" in config["mcpServers"]
        assert "enforcement-mcp" in config["mcpServers"]


class TestCmdSetup:
    def test_no_target_exits(self):
        with pytest.raises(SystemExit):
            cmd_setup(None)

    def test_no_clients_prints_snippet(self, capsys, monkeypatch):
        monkeypatch.setattr("enforcement_mcp.cli._detect_clients", lambda: [])
        cmd_setup("myhost.example.com")
        output = capsys.readouterr().out
        assert "enforcement-mcp" in output
        assert "myhost.example.com" in output
