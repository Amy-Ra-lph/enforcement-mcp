"""Tests for the assess_risk tool's boolean path."""

from enforcement_mcp.tools.risk import assess_risk

from .conftest import make_result


async def test_boolean_name_injection_rejected(mock_ssh):
    commands: list[str] = []

    async def fake_execute(cmd, timeout=30):
        commands.append(cmd)
        return make_result("Enforcing\n")

    mock_ssh.execute = fake_execute
    result = await assess_risk(mock_ssh, "boolean", name="x; touch /tmp/pwned", value=True)

    assert result["error"] == "invalid_input"
    assert not any("touch" in c for c in commands)


async def test_boolean_name_quoted(mock_ssh):
    commands: list[str] = []

    async def fake_execute(cmd, timeout=30):
        commands.append(cmd)
        return make_result("Enforcing\n" if cmd == "getenforce" else "")

    mock_ssh.execute = fake_execute
    await assess_risk(mock_ssh, "boolean", name="httpd_can_network_connect", value=True)

    assert "sesearch --allow -b httpd_can_network_connect 2>/dev/null" in commands
