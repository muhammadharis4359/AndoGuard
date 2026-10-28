"""Tests for Milestone 9: Multi-Format Reporting and Session Bundle Export/Import."""

import json
from pathlib import Path

from typer.testing import CliRunner

from andoguard.api import AndoGuard
from andoguard.cli.main import app
from andoguard.config import AndoGuardConfig
from andoguard.models import FindingConfidence, FindingSeverity, TraceEvent

runner = CliRunner()


def test_report_generation(sample_apk_path: Path) -> None:
    with AndoGuard.open(sample_apk_path) as ag:
        # Markdown
        md = ag.generate_report(format="markdown")
        assert "# AndoGuard Security Assessment Report" in md
        assert "Executive Vulnerability Summary" in md
        assert "Security Manifest Flags" in md
        assert "Signature & Certificate Audit" in md

        # JSON
        json_rep = ag.generate_report(format="json")
        data = json.loads(json_rep)
        assert "metadata" in data
        assert "security_flags" in data
        assert "findings" in data
        assert "severity_summary" in data

        # HTML
        html_rep = ag.generate_report(format="html")
        assert "<!DOCTYPE html>" in html_rep
        assert "AndoGuard Security Assessment Report" in html_rep
        assert "--bg-primary:" in html_rep
        assert "Executive Vulnerability Summary" not in html_rep  # Uses visual grid metrics


def test_cli_report_command(sample_apk_path: Path, tmp_path: Path) -> None:
    open_res = runner.invoke(app, ["open", str(sample_apk_path)])
    assert open_res.exit_code == 0

    # Default Markdown report
    res_md = runner.invoke(app, ["report"])
    assert res_md.exit_code == 0
    assert "Security Assessment Report" in res_md.stdout

    # JSON report
    res_json = runner.invoke(app, ["report", "--format", "json"])
    assert res_json.exit_code == 0
    assert '"package_name":' in res_json.stdout

    # HTML report to file
    html_file = tmp_path / "assessment_report.html"
    res_html = runner.invoke(app, ["report", "--format", "html", "--out", str(html_file)])
    assert res_html.exit_code == 0
    assert html_file.exists()
    assert "<!DOCTYPE html>" in html_file.read_text(encoding="utf-8")


def test_session_bundle_export_import(sample_apk_path: Path, tmp_path: Path) -> None:
    bundle_path = tmp_path / "test_session.agguard"

    with AndoGuard.open(sample_apk_path) as ag:
        # Add finding
        ag.session_store.record_finding(
            session_id=ag.session_record.session_id,
            title="Custom Hardcoded Token in Test",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.HIGH,
            evidence="Bearer eyJhbGciOi...",
            remediation="Use secure Android Keystore.",
            masvs_id="MASVS-STORAGE-1",
        )
        # Add trace event
        ag.save_trace_event(
            TraceEvent(
                timestamp="2026-10-28T16:00:00Z",
                event_type="call",
                class_name="com.example.Crypto",
                method_name="decryptData",
                args=["cipher_text_123"],
                return_val=None,
            )
        )
        sid = ag.session.id
        ag.export_bundle(out_path=bundle_path)

    assert bundle_path.exists()

    # Import bundle into a fresh workspace
    import_cfg = AndoGuardConfig(work_dir=tmp_path / "imported_workspace")
    import_cfg.ensure_directories()

    imported_record = AndoGuard.import_bundle(bundle_path, work_dir=import_cfg.work_dir)
    assert imported_record.session_id == sid

    # Verify session store in new workspace
    from andoguard.session.store import SessionStore

    new_store = SessionStore(import_cfg)
    findings = new_store.get_findings(sid)
    assert len(findings) >= 1
    assert any(f.title == "Custom Hardcoded Token in Test" for f in findings)

    traces = new_store.get_trace_events(sid)
    assert len(traces) >= 1
    assert any(t.method_name == "decryptData" for t in traces)


def test_cli_export_and_import(sample_apk_path: Path, tmp_path: Path) -> None:
    open_res = runner.invoke(app, ["open", str(sample_apk_path)])
    assert open_res.exit_code == 0

    bundle_file = tmp_path / "cli_exported.agguard"
    export_res = runner.invoke(app, ["export", "--out", str(bundle_file)])
    assert export_res.exit_code == 0
    assert bundle_file.exists()

    # Import via CLI
    import_res = runner.invoke(app, ["import", str(bundle_file)])
    assert import_res.exit_code == 0
    assert "Successfully imported session" in import_res.stdout
