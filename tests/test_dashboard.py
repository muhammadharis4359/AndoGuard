"""Tests for AndoGuard Modern Web Dashboard."""

from pathlib import Path

from typer.testing import CliRunner

from andoguard.cli.main import app
from andoguard.dashboard.server import AndoGuardDashboardServer

runner = CliRunner()


def test_dashboard_server_initialization() -> None:
    sample_apk = Path("samples/insecure_bank.apk")
    manager = AndoGuardDashboardServer(target_path=sample_apk if sample_apk.exists() else None)

    status = manager.get_status()
    assert "active" in status
    assert "samples" in status

    overview = manager.get_overview_data()
    assert "security_score" in overview
    assert "risk_grade" in overview
    assert "findings" in overview
    assert "severity_summary" in overview
    assert "security_flags" in overview


def test_dashboard_code_and_frida_generator() -> None:
    manager = AndoGuardDashboardServer()
    code_res = manager.get_code_data("com.andoguard.insecurebank.AuthManager", lang="java")
    assert "AuthManager" in code_res["source"]
    assert "DES" in code_res["source"]

    code_dalvik = manager.get_code_data("com.andoguard.insecurebank.AuthManager", lang="dalvik")
    assert ".class" in code_dalvik["source"] or "AuthManager" in code_dalvik["source"]

    script_ssl = manager.generate_frida_script("ssl_bypass")
    assert "checkTrustedRecursive" in script_ssl or "Java.perform" in script_ssl

    script_root = manager.generate_frida_script("root_bypass")
    assert "release-keys" in script_root or "Java.perform" in script_root


def test_dashboard_ai_co_pilot() -> None:
    manager = AndoGuardDashboardServer()
    ans = manager.answer_ai_question("Provide an executive summary for my professor.")
    assert "answer" in ans
    assert "Executive" in ans["answer"] or "AndoGuard" in ans["answer"]


def test_dashboard_cli_command_help() -> None:
    res = runner.invoke(app, ["dashboard", "--help"])
    assert res.exit_code == 0
    assert "interactive modern web dashboard" in res.stdout


def test_standalone_dashboard_html_file() -> None:
    dash_file = Path("dashboard.html")
    assert dash_file.exists()
    content = dash_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "AndoGuard" in content
    assert "scoreRadialCircle" in content
