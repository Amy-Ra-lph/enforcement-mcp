"""Tests for remediation playbook generator."""

import pytest
import yaml

from enforcement_mcp.tools.remediate import generate_playbook

SYSTEM_ROLES = "fedora.linux_system_roles"


class MockSSH:
    def __init__(self, responses=None):
        self._responses = responses or {}

    async def execute(self, cmd):
        for pattern, resp in self._responses.items():
            if pattern in cmd:
                return resp
        return type("R", (), {"success": False, "stdout": "", "exit_code": 1})()


def make_result(stdout, exit_code=0):
    return type(
        "R", (),
        {"success": exit_code == 0, "stdout": stdout, "exit_code": exit_code},
    )()


class TestDenialRemediation:
    @pytest.mark.asyncio
    async def test_denial_with_boolean(self):
        ssh = MockSSH({
            "sesearch": make_result(
                "allow httpd_t user_home_t : file { read } "
                "[ httpd_read_user_content ]:True\n"
            ),
        })
        result = await generate_playbook(
            ssh, "denial",
            source_type="httpd_t", target_type="user_home_t",
            tclass="file", permission="read", path="/home/user/index.html",
        )
        assert result["finding_type"] == "denial"
        assert result["total_options"] >= 2
        assert any(
            a["strategy"] == "boolean" for a in result["alternatives"]
        )
        assert any(
            a["strategy"] == "relabel" for a in result["alternatives"]
        )
        # Relabel should be recommended (lowest risk)
        assert result["recommended"]["strategy"] == "relabel"

    @pytest.mark.asyncio
    async def test_denial_without_path(self):
        ssh = MockSSH({"sesearch": make_result("")})
        result = await generate_playbook(
            ssh, "denial",
            source_type="httpd_t", target_type="etc_t",
            tclass="file", permission="write",
        )
        assert result["finding_type"] == "denial"
        # No relabel option without a path
        assert not any(
            a["strategy"] == "relabel" for a in result["alternatives"]
        )
        # Should still have custom_module
        assert any(
            a["strategy"] == "custom_module" for a in result["alternatives"]
        )

    @pytest.mark.asyncio
    async def test_denial_missing_params(self):
        result = await generate_playbook(
            None, "denial", source_type="httpd_t",
        )
        assert "error" in result

    @pytest.mark.asyncio
    async def test_denial_risk_in_playbook(self):
        ssh = MockSSH({"sesearch": make_result("")})
        result = await generate_playbook(
            ssh, "denial",
            source_type="httpd_t", target_type="shadow_t",
            tclass="file", permission="read",
        )
        module_alt = next(
            a for a in result["alternatives"]
            if a["strategy"] == "custom_module"
        )
        # shadow_t is high-sensitivity target
        assert module_alt["risk"]["risk_score"] > 30

    @pytest.mark.asyncio
    async def test_playbook_yaml_valid(self):
        ssh = MockSSH({"sesearch": make_result("")})
        result = await generate_playbook(
            ssh, "denial",
            source_type="httpd_t", target_type="tmp_t",
            tclass="file", permission="write",
        )
        for alt in result["alternatives"]:
            pb_text = alt["playbook"]
            # Extract YAML after the --- line
            yaml_part = pb_text.split("---\n", 1)[1]
            parsed = yaml.safe_load(yaml_part)
            assert isinstance(parsed, list)
            assert parsed[0]["become"] is True

    @pytest.mark.asyncio
    async def test_alternatives_sorted_by_risk(self):
        ssh = MockSSH({
            "sesearch": make_result(
                "allow httpd_t user_home_t : file { read getattr open } "
                "[ httpd_read_user_content ]:True\n"
            ),
        })
        result = await generate_playbook(
            ssh, "denial",
            source_type="httpd_t", target_type="user_home_t",
            tclass="file", permission="read", path="/home/user/f.txt",
        )
        scores = [a["risk"]["risk_score"] for a in result["alternatives"]]
        assert scores == sorted(scores)


class TestFileContextRemediation:
    @pytest.mark.asyncio
    async def test_mismatch_generates_restorecon(self):
        result = await generate_playbook(
            None, "file_context",
            path="/var/www/html/app.log",
            expected_type="httpd_sys_content_t",
            actual_type="var_log_t",
        )
        assert result["finding_type"] == "file_context"
        assert result["recommended"]["strategy"] == "restorecon"
        assert SYSTEM_ROLES in result["recommended"]["playbook"]

    @pytest.mark.asyncio
    async def test_fcontext_rule_option(self):
        result = await generate_playbook(
            None, "file_context",
            path="/opt/myapp/data",
            expected_type="httpd_sys_content_t",
            actual_type="default_t",
        )
        assert any(
            a["strategy"] == "fcontext_rule"
            for a in result["alternatives"]
        )

    @pytest.mark.asyncio
    async def test_missing_path(self):
        result = await generate_playbook(None, "file_context")
        assert "error" in result


class TestFapolicydRemediation:
    @pytest.mark.asyncio
    async def test_trust_path(self):
        result = await generate_playbook(
            None, "fapolicyd_block", path="/opt/myapp/bin/worker",
        )
        assert result["finding_type"] == "fapolicyd_block"
        assert result["recommended"]["strategy"] == "trust_path"
        assert "risk" in result["recommended"]
        assert SYSTEM_ROLES in result["recommended"]["playbook"]

    @pytest.mark.asyncio
    async def test_tmp_path_high_risk(self):
        result = await generate_playbook(
            None, "fapolicyd_block", path="/tmp/sketchy_binary",
        )
        assert result["recommended"]["risk"]["risk_score"] >= 30

    @pytest.mark.asyncio
    async def test_missing_path(self):
        result = await generate_playbook(None, "fapolicyd_block")
        assert "error" in result


class TestAideRemediation:
    @pytest.mark.asyncio
    async def test_investigate_default(self):
        result = await generate_playbook(
            None, "aide_change",
            changed_paths=["/etc/hosts", "/etc/resolv.conf"],
        )
        assert result["finding_type"] == "aide_change"
        assert result["action"] == "investigate"
        assert result["total_options"] == 0

    @pytest.mark.asyncio
    async def test_accept_generates_playbook(self):
        result = await generate_playbook(
            None, "aide_change",
            changed_paths=["/etc/hosts"],
            action="accept",
        )
        assert result["recommended"]["strategy"] == "update_baseline"
        assert "warning" in result
        assert SYSTEM_ROLES in result["recommended"]["playbook"]
        assert result["recommended"]["risk"]["risk_level"] == "medium"

    @pytest.mark.asyncio
    async def test_accept_risk_scales_with_changes(self):
        result = await generate_playbook(
            None, "aide_change",
            changed_paths=[f"/etc/file{i}" for i in range(50)],
            action="accept",
        )
        blast = result["recommended"]["risk"]["blast_radius"]
        assert blast["files_accepted"] == 50


class TestUnknownFindingType:
    @pytest.mark.asyncio
    async def test_unknown_type(self):
        result = await generate_playbook(None, "something_else")
        assert "error" in result
        assert "supported" in result


class TestPlaybookStructure:
    @pytest.mark.asyncio
    async def test_uses_system_roles_collection(self):
        result = await generate_playbook(
            None, "fapolicyd_block", path="/usr/local/bin/myapp",
        )
        pb = result["recommended"]["playbook"]
        assert SYSTEM_ROLES in pb

    @pytest.mark.asyncio
    async def test_target_is_variable(self):
        result = await generate_playbook(
            None, "fapolicyd_block", path="/usr/local/bin/myapp",
        )
        pb = result["recommended"]["playbook"]
        yaml_part = pb.split("---\n", 1)[1]
        parsed = yaml.safe_load(yaml_part)
        assert "{{ target_hosts }}" in parsed[0]["hosts"]

    @pytest.mark.asyncio
    async def test_risk_comment_in_header(self):
        result = await generate_playbook(
            None, "fapolicyd_block", path="/tmp/risky",
        )
        pb = result["recommended"]["playbook"]
        assert "# Risk:" in pb
        assert "# Generated by enforcement-mcp" in pb
