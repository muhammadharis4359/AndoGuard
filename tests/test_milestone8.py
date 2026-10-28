"""Tests for Milestone 8: Adaptive Autonomous Mode, Typed Tool Registry, and Agent Loop."""

from pathlib import Path

from typer.testing import CliRunner

from andoguard.adaptive.agent import AdaptiveAgent
from andoguard.adaptive.tools import create_default_registry
from andoguard.ai.provider import MockAiProvider
from andoguard.api import AndoGuard
from andoguard.cli.main import app

runner = CliRunner()


def test_tool_registry(sample_apk_path: Path) -> None:
    registry = create_default_registry()
    tools = registry.list_tools()
    tool_names = {t.name for t in tools}

    assert "get_manifest_info" in tool_names
    assert "list_classes" in tool_names
    assert "decompile_class" in tool_names
    assert "find_methods" in tool_names
    assert "disassemble_method" in tool_names
    assert "find_xrefs" in tool_names
    assert "scan_secrets" in tool_names
    assert "audit_vulns" in tool_names
    assert "search_strings" in tool_names
    assert "inspect_native" in tool_names
    assert "generate_hook" in tool_names
    assert "record_finding" in tool_names

    schemas = registry.get_schemas()
    assert len(schemas) == len(tools)
    assert any(s["name"] == "audit_vulns" for s in schemas)

    with AndoGuard.open(sample_apk_path) as ag:
        # Test executing tools through registry
        manifest_data = registry.execute("get_manifest_info", ag, {})
        assert "package_name" in manifest_data

        vulns_data = registry.execute("audit_vulns", ag, {})
        assert "summary" in vulns_data
        assert "findings" in vulns_data

        classes_data = registry.execute("list_classes", ag, {"limit": 10})
        assert isinstance(classes_data, list)


def test_deterministic_walker(sample_apk_path: Path) -> None:
    with AndoGuard.open(sample_apk_path) as ag:
        agent = AdaptiveAgent(autonomy_level="full", max_steps=5)
        # Without AI provider, agent defaults to deterministic walker
        res = agent.run(ag, goal="Audit crypto and sensitive keys")

        assert res.goal == "Audit crypto and sensitive keys"
        assert len(res.steps) >= 3
        assert any(s.tool_name == "get_manifest_info" for s in res.steps)
        assert any(s.tool_name == "audit_vulns" for s in res.steps)
        assert any(s.tool_name == "scan_secrets" for s in res.steps)
        assert any(s.status == "success" for s in res.steps)
        assert "Deterministic autonomous walker completed" in res.summary


def test_assist_mode_planning(sample_apk_path: Path) -> None:
    with AndoGuard.open(sample_apk_path) as ag:
        agent = AdaptiveAgent(autonomy_level="assist")
        res = agent.run(ag, goal="Analyze authentication and session management")

        assert res.autonomy_level == "assist"
        assert len(res.steps) == 0  # No tools executed
        assert "Plan generated in ASSIST mode" in res.summary

        plan_steps = ag.adaptive_plan(goal="Reverse engineer payment gateway")
        assert len(plan_steps) >= 3


def test_react_loop_with_mock_ai(sample_apk_path: Path) -> None:
    with AndoGuard.open(sample_apk_path) as ag:
        # Create a mock provider that returns a 2-step ReAct sequence
        mock_p = MockAiProvider()
        # Set canned ReAct response: step 1 call get_manifest_info, step 2 finish
        mock_p.default_response = (
            '{"thought": "Inspect manifest for exported components", '
            '"tool": "get_manifest_info", "args": {}, "finished": false}'
        )

        agent = AdaptiveAgent(autonomy_level="full", max_steps=2)
        res = agent.run(ag, goal="Audit attack surface", provider="mock")

        assert len(res.steps) >= 1
        assert res.steps[0].tool_name == "get_manifest_info"
        assert res.steps[0].status == "success"


def test_cli_adaptive_commands(sample_apk_path: Path) -> None:
    # Open APK session first
    open_res = runner.invoke(app, ["open", str(sample_apk_path)])
    assert open_res.exit_code == 0

    # Plan
    plan_res = runner.invoke(app, ["adaptive", "plan", "Audit credentials and cryptography"])
    assert plan_res.exit_code == 0
    assert "Autonomous Execution Plan" in plan_res.stdout

    # Run
    run_res = runner.invoke(app, ["adaptive", "run", "Comprehensive security check", "--max-steps", "4"])
    assert run_res.exit_code == 0
    assert "Autonomous Execution" in run_res.stdout
    assert "Assessment Summary" in run_res.stdout

    # Run JSON
    json_res = runner.invoke(app, ["adaptive", "run", "Security audit", "--json", "--max-steps", "3"])
    assert json_res.exit_code == 0
    assert '"goal": "Security audit"' in json_res.stdout
