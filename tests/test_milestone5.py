"""Comprehensive tests for Milestone 5: Dynamic Instrumentation, Frida Bridge, and Method Tracing."""

import json
from pathlib import Path

from typer.testing import CliRunner

from andoguard.adapters.frida_bridge import FridaBridge
from andoguard.api import AndoGuard
from andoguard.cli.main import app
from andoguard.dynamic.generator import (
    generate_java_class_hook,
    generate_java_method_hook,
    generate_native_hook,
)
from andoguard.dynamic.tracer import MethodTracer, generate_pattern_tracer_script
from andoguard.models import TraceEvent

runner = CliRunner()


def test_frida_bridge_simulation_mode() -> None:
    """Verify FridaBridge functions properly in simulation mode for offline/mock environments."""
    bridge = FridaBridge(simulation_mode=True)
    assert bridge.is_available()

    devices = bridge.get_devices()
    assert len(devices) >= 2
    assert any(d.is_emulator for d in devices)

    procs = bridge.list_processes()
    assert len(procs) >= 1
    pids = [p.pid for p in procs]
    assert 2048 in pids

    pid = bridge.spawn("com.example.testapp", auto_resume=True)
    assert pid == 2048

    session = bridge.attach("com.example.testapp")
    assert session is not None

    script = bridge.inject_script(session, "console.log('test');")
    assert script is not None

    bridge.resume(pid)
    bridge.kill(pid)
    remaining_pids = [p.pid for p in bridge.list_processes()]
    assert pid not in remaining_pids


def test_hook_generators() -> None:
    """Verify Java and native hook script generation."""
    # Java method hook
    m_script = generate_java_method_hook(
        "com.example.AuthService", "login", dump_backtrace=True, custom_return="true"
    )
    assert "Java.perform" in m_script
    assert "com.example.AuthService" in m_script
    assert "login" in m_script
    assert "getStackTraceString" in m_script
    assert "return true;" in m_script

    # Java class hook
    c_script = generate_java_class_hook("com.example.SecurityManager")
    assert "Java.perform" in c_script
    assert "com.example.SecurityManager" in c_script
    assert "getDeclaredMethods" in c_script

    # Native hook
    n_script = generate_native_hook("strcmp", library_name="libc.so")
    assert "Module.findExportByName" in n_script
    assert "Interceptor.attach" in n_script
    assert "strcmp" in n_script
    assert "libc.so" in n_script


def test_tracer_script_and_event_handling() -> None:
    """Test pattern-based tracer generation and real-time message handling."""
    script = generate_pattern_tracer_script("com.example.*!on*")
    assert "Java.enumerateLoadedClasses" in script
    assert "com.example.*" in script
    assert "on*" in script

    # Test event handler
    events_received: list[TraceEvent] = []
    tracer = MethodTracer(on_event=lambda ev: events_received.append(ev))

    call_msg = {
        "type": "send",
        "payload": {
            "event_type": "call",
            "class_name": "com.example.MainActivity",
            "method_name": "onCreate",
            "args": ["null"],
        },
    }
    tracer.handle_message(call_msg)
    assert len(tracer.events) == 1
    assert len(events_received) == 1
    assert tracer.events[0].class_name == "com.example.MainActivity"
    assert tracer.events[0].method_name == "onCreate"

    ret_msg = {
        "type": "send",
        "payload": {
            "event_type": "return",
            "class_name": "com.example.MainActivity",
            "method_name": "onCreate",
            "return_val": "void/null",
        },
    }
    tracer.handle_message(ret_msg)
    assert len(tracer.events) == 2
    assert tracer.events[1].return_val == "void/null"


def test_api_dynamic_features(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test dynamic API methods on AndoGuard instance."""
    with AndoGuard.open(
        sample_apk_path, session_name="m5-api-test", work_dir=tmp_path
    ) as ag:
        devices = ag.devices(simulation_mode=True)
        assert len(devices) > 0

        procs = ag.processes(simulation_mode=True)
        assert len(procs) > 0

        pid = ag.spawn("com.example.testapp", simulation_mode=True)
        assert pid > 0

        hook_code = ag.generate_hook("com.example.MainActivity#onCreate")
        assert "onCreate" in hook_code

        tracer_code = ag.generate_tracer("com.example.*")
        assert "Java.enumerateLoadedClasses" in tracer_code


def test_cli_dynamic_devices() -> None:
    """Test CLI 'andoguard dynamic devices' command."""
    res = runner.invoke(app, ["dynamic", "devices", "--simulation"])
    assert res.exit_code == 0
    assert "Connected Devices" in res.output

    json_res = runner.invoke(app, ["dynamic", "devices", "--simulation", "--json"])
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert isinstance(parsed, list)
    assert len(parsed) >= 2


def test_cli_dynamic_ps() -> None:
    """Test CLI 'andoguard dynamic ps' command."""
    res = runner.invoke(app, ["dynamic", "ps", "--simulation"])
    assert res.exit_code == 0
    assert "Running Processes" in res.output

    json_res = runner.invoke(app, ["dynamic", "ps", "--simulation", "--json"])
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert isinstance(parsed, list)


def test_cli_dynamic_spawn_resume_kill() -> None:
    """Test CLI 'andoguard dynamic spawn/resume/kill' commands."""
    spawn_res = runner.invoke(
        app,
        ["dynamic", "spawn", "com.example.testapp", "--simulation", "--json"],
    )
    assert spawn_res.exit_code == 0
    parsed = json.loads(spawn_res.output)
    assert parsed["package"] == "com.example.testapp"
    assert parsed["pid"] == 2048

    resume_res = runner.invoke(app, ["dynamic", "resume", "2048", "--simulation"])
    assert resume_res.exit_code == 0
    assert "Resumed process" in resume_res.output

    kill_res = runner.invoke(app, ["dynamic", "kill", "2048", "--simulation"])
    assert kill_res.exit_code == 0
    assert "Terminated process" in kill_res.output


def test_cli_dynamic_gen() -> None:
    """Test CLI 'andoguard dynamic gen' command."""
    # Java method
    res = runner.invoke(app, ["dynamic", "gen", "com.example.MainActivity#onCreate"])
    assert res.exit_code == 0
    assert "Java.perform" in res.output
    assert "onCreate" in res.output

    # Native function
    native_res = runner.invoke(app, ["dynamic", "gen", "open", "--native", "--lib", "libc.so"])
    assert native_res.exit_code == 0
    assert "Interceptor.attach" in native_res.output
    assert "libc.so" in native_res.output


def test_cli_dynamic_trace() -> None:
    """Test CLI 'andoguard dynamic trace' command."""
    res = runner.invoke(app, ["dynamic", "trace", "com.example.*"])
    assert res.exit_code == 0
    assert "Java.enumerateLoadedClasses" in res.output
