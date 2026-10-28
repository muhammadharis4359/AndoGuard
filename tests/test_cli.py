"""Tests for AndoGuard CLI commands."""

import json
from pathlib import Path

from typer.testing import CliRunner

from andoguard.cli.main import app

runner = CliRunner()


def test_cli_version_notice() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "AndoGuard version" in result.output
    # Mandated authorized use notice
    assert "AUTHORIZED SECURITY TESTING" in result.output


def test_cli_open_and_info(sample_apk_path: Path, tmp_path: Path) -> None:
    work_dir = tmp_path / "cli_work"

    # 1. Open target
    open_res = runner.invoke(
        app,
        [
            "open",
            str(sample_apk_path),
            "--name",
            "cli-test",
            "--work-dir",
            str(work_dir),
        ],
    )
    assert open_res.exit_code == 0
    assert "Target Summary" in open_res.output or "Session ID" in open_res.output

    # 2. Inspect with 'info'
    info_res = runner.invoke(
        app,
        ["info", "--work-dir", str(work_dir)],
    )
    assert info_res.exit_code == 0
    assert "Target Information" in info_res.output
    assert "SHA-256" in info_res.output

    # 3. Inspect with 'info --json'
    info_json_res = runner.invoke(
        app,
        ["info", "--json", "--work-dir", str(work_dir)],
    )
    assert info_json_res.exit_code == 0
    data = json.loads(info_json_res.output)
    assert "sha256" in data
    assert data["target_type"] == "apk"

    # 4. List sessions
    sessions_res = runner.invoke(
        app,
        ["sessions", "--work-dir", str(work_dir)],
    )
    assert sessions_res.exit_code == 0
    assert "cli-test" in sessions_res.output

    # 5. Resume session
    resume_res = runner.invoke(
        app,
        ["resume", "cli-test", "--work-dir", str(work_dir)],
    )
    assert resume_res.exit_code == 0
    assert "Resumed session" in resume_res.output


def test_cli_open_json_output(sample_apk_path: Path, tmp_path: Path) -> None:
    work_dir = tmp_path / "cli_work_json"
    result = runner.invoke(
        app,
        ["open", str(sample_apk_path), "--json", "--work-dir", str(work_dir)],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert "sha256" in parsed
    assert "target_type" in parsed


def test_cli_nonexistent_target(tmp_path: Path) -> None:
    missing = tmp_path / "nonexistent.apk"
    result = runner.invoke(app, ["open", str(missing)])
    assert result.exit_code != 0
    # Expected clean failure, no uncaught exception traceback
    assert "Traceback" not in result.output
