"""Tests for Milestone 6: Security Bypasses, Memory Operations, and Trace Persistence."""

from pathlib import Path

from typer.testing import CliRunner

from andoguard.api import AndoGuard
from andoguard.cli.main import app
from andoguard.dynamic.bypasses import (
    generate_combined_bypass,
    generate_debugger_bypass,
    generate_emulator_bypass,
    generate_root_bypass,
    generate_ssl_pinning_bypass,
)
from andoguard.dynamic.memory import (
    format_hexdump,
    generate_memory_dump_script,
    generate_memory_search_script,
)
from andoguard.models import TraceEvent

runner = CliRunner()


def test_ssl_pinning_bypass() -> None:
    script = generate_ssl_pinning_bypass()
    assert "TrustManagerImpl" in script
    assert "CertificatePinner" in script
    assert "onReceivedSslError" in script


def test_root_detection_bypass() -> None:
    script = generate_root_bypass()
    assert "/sbin/su" in script
    assert "magisk" in script
    assert "release-keys" in script


def test_debugger_and_emulator_bypasses() -> None:
    dbg = generate_debugger_bypass()
    assert "isDebuggerConnected" in script if (script := dbg) else False
    assert "waitingForDebugger" in dbg

    emu = generate_emulator_bypass()
    assert "Pixel 7 Pro" in emu
    assert "cheetah" in emu


def test_combined_bypass() -> None:
    all_bypasses = generate_combined_bypass()
    assert "SSL Pinning" in all_bypasses
    assert "Root Detection" in all_bypasses
    assert "Debugger Detection" in all_bypasses
    assert "Emulator Detection" in all_bypasses

    selective = generate_combined_bypass(["ssl", "root"])
    assert "SSL Pinning" in selective
    assert "Root Detection" in selective
    assert "Emulator Detection" not in selective


def test_memory_hexdump_and_scripts() -> None:
    data = b"Hello, World!\x00\x01\x02\xff"
    dump_text = format_hexdump(data, base_address=0x1000)
    assert "00001000:" in dump_text
    assert "48 65 6c 6c 6f" in dump_text
    assert "|Hello, World!...|" in dump_text

    search_str = generate_memory_search_script("password")
    assert "Process.enumerateRanges('r--')" in search_str
    assert "Memory.scan" in search_str

    search_hex = generate_memory_search_script("de ad be ef", is_hex=True)
    assert '"de ad be ef"' in search_hex

    dump_script = generate_memory_dump_script("0x7fff1000", 128)
    assert 'ptr("0x7fff1000")' in dump_script
    assert "readByteArray(128)" in dump_script


def test_api_bypasses_and_memory(sample_apk_path: Path) -> None:
    with AndoGuard.open(sample_apk_path) as ag:
        ssl_bypass = ag.bypass("ssl")
        assert "TrustManagerImpl" in ssl_bypass

        mem_script = ag.search_memory("flag_token")
        assert "Memory.scan" in mem_script

        dump_script = ag.dump_memory("0x12345678", 64)
        assert "0x12345678" in dump_script


def test_trace_and_hook_persistence(sample_apk_path: Path) -> None:
    with AndoGuard.open(sample_apk_path) as ag:
        event1 = TraceEvent(
            timestamp="2026-10-28T12:00:00Z",
            event_type="call",
            class_name="com.example.Auth",
            method_name="login",
            args=["admin", "secret123"],
            return_val=None,
        )
        event2 = TraceEvent(
            timestamp="2026-10-28T12:00:01Z",
            event_type="return",
            class_name="com.example.Auth",
            method_name="login",
            args=[],
            return_val="true",
        )
        ag.save_trace_event(event1)
        ag.save_trace_event(event2)

        traces = ag.trace_events()
        assert len(traces) >= 2
        assert any(t.method_name == "login" and t.event_type == "call" for t in traces)
        assert any(t.return_val == "true" for t in traces)

        hook_id = ag.save_hook(
            class_name="com.example.Auth",
            method_name="login",
            script="// hook script",
            status="active",
        )
        assert hook_id is not None
        hooks = ag.hooks()
        assert len(hooks) >= 1
        assert any(h["method_name"] == "login" for h in hooks)


def test_cli_dynamic_bypasses(tmp_path: Path) -> None:
    res = runner.invoke(app, ["dynamic", "bypass", "ssl"])
    assert res.exit_code == 0
    assert "TrustManagerImpl" in res.stdout

    out_file = tmp_path / "all_bypasses.js"
    res2 = runner.invoke(app, ["dynamic", "bypass", "all", "--out", str(out_file)])
    assert res2.exit_code == 0
    assert out_file.exists()
    assert "Pixel 7 Pro" in out_file.read_text(encoding="utf-8")


def test_cli_dynamic_mem() -> None:
    res1 = runner.invoke(app, ["dynamic", "mem", "search", "admin_key"])
    assert res1.exit_code == 0
    assert "Memory.scan" in res1.stdout

    res2 = runner.invoke(app, ["dynamic", "mem", "dump", "0x7fff0000", "256"])
    assert res2.exit_code == 0
    assert "readByteArray(256)" in res2.stdout


def test_cli_dynamic_traces_and_replay(sample_apk_path: Path) -> None:
    # Create session with trace event
    with AndoGuard.open(sample_apk_path) as ag:
        ag.save_trace_event(
            TraceEvent(
                timestamp="2026-10-28T12:30:00Z",
                event_type="call",
                class_name="com.example.Target",
                method_name="verifyLicense",
                args=["license_key_123"],
                return_val=None,
            )
        )
        sid = ag.session.id

    res = runner.invoke(app, ["dynamic", "traces", "--session", sid, "--json"])
    assert res.exit_code == 0
    assert "verifyLicense" in res.stdout

    replay_res = runner.invoke(app, ["dynamic", "replay", sid, "--delay", "0"])
    assert replay_res.exit_code == 0
    assert "verifyLicense" in replay_res.stdout
    assert "Trace replay finished" in replay_res.stdout
