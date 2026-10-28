"""CLI subcommands for dynamic instrumentation ('andoguard dynamic ...')."""

import json
import time
from pathlib import Path

import typer

from andoguard.adapters.frida_bridge import FridaBridge
from andoguard.cli.render import (
    console,
    render_devices,
    render_error,
    render_processes,
    render_trace_event,
    render_trace_events,
    status_spinner,
)
from andoguard.config import AndoGuardConfig
from andoguard.dynamic.bypasses import generate_combined_bypass
from andoguard.dynamic.generator import (
    generate_java_class_hook,
    generate_java_method_hook,
    generate_native_hook,
)
from andoguard.dynamic.memory import (
    generate_memory_dump_script,
    generate_memory_search_script,
)
from andoguard.dynamic.tracer import generate_pattern_tracer_script
from andoguard.errors import AndoGuardError
from andoguard.session.store import SessionStore

dynamic_app = typer.Typer(
    name="dynamic",
    help="Dynamic instrumentation, Frida runtime hooking, and device interaction.",
    no_args_is_help=True,
)

mem_app = typer.Typer(
    name="mem",
    help="Process memory inspection, range scanning, and dumping.",
    no_args_is_help=True,
)
dynamic_app.add_typer(mem_app)


@dynamic_app.command(name="devices", help="List connected Android devices and emulators.")
def list_devices(
    simulation: bool = typer.Option(
        False,
        "--simulation",
        help="Run in simulation mode for offline or mock testing.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output device list in JSON format.",
    ),
) -> None:
    try:
        bridge = FridaBridge(simulation_mode=simulation)
        with status_spinner("Scanning for connected devices...", enabled=not json_output):
            devices = bridge.get_devices()
        render_devices(devices, as_json=json_output)
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@dynamic_app.command(name="ps", help="List running processes on target Android device.")
def list_processes(
    device_id: str | None = typer.Option(
        None,
        "--device",
        "-d",
        help="Target device ID. Defaults to first USB/emulator device.",
    ),
    simulation: bool = typer.Option(
        False,
        "--simulation",
        help="Run in simulation mode for offline or mock testing.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output running processes in JSON format.",
    ),
) -> None:
    try:
        bridge = FridaBridge(simulation_mode=simulation)
        with status_spinner("Enumerating processes...", enabled=not json_output):
            procs = bridge.list_processes(device_id=device_id)
        render_processes(procs, as_json=json_output)
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@dynamic_app.command(name="spawn", help="Spawn target package in suspended or running state.")
def spawn_package(
    package_name: str = typer.Argument(..., help="Package identifier (e.g. 'com.example.app')."),
    device_id: str | None = typer.Option(
        None,
        "--device",
        "-d",
        help="Target device ID.",
    ),
    auto_resume: bool = typer.Option(
        False,
        "--resume",
        "-r",
        help="Automatically resume process after spawning.",
    ),
    simulation: bool = typer.Option(
        False,
        "--simulation",
        help="Run in simulation mode.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output spawned PID in JSON format.",
    ),
) -> None:
    try:
        bridge = FridaBridge(simulation_mode=simulation)
        with status_spinner(f"Spawning '{package_name}'...", enabled=not json_output):
            pid = bridge.spawn(package_name, device_id=device_id, auto_resume=auto_resume)
        if json_output:
            print(json.dumps({"package": package_name, "pid": pid, "resumed": auto_resume}, indent=2))
        else:
            console.print(f"[bold green]Successfully spawned[/bold green] '{package_name}' with PID [bold yellow]{pid}[/bold yellow]")
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@dynamic_app.command(name="resume", help="Resume a suspended target process.")
def resume_process(
    pid: int = typer.Argument(..., help="Process ID to resume."),
    device_id: str | None = typer.Option(
        None,
        "--device",
        "-d",
        help="Target device ID.",
    ),
    simulation: bool = typer.Option(
        False,
        "--simulation",
        help="Run in simulation mode.",
    ),
) -> None:
    try:
        bridge = FridaBridge(simulation_mode=simulation)
        bridge.resume(pid, device_id=device_id)
        console.print(f"[bold green]Resumed process[/bold green] [bold yellow]{pid}[/bold yellow]")
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@dynamic_app.command(name="kill", help="Kill a running process on device.")
def kill_process(
    pid: int = typer.Argument(..., help="Process ID to terminate."),
    device_id: str | None = typer.Option(
        None,
        "--device",
        "-d",
        help="Target device ID.",
    ),
    simulation: bool = typer.Option(
        False,
        "--simulation",
        help="Run in simulation mode.",
    ),
) -> None:
    try:
        bridge = FridaBridge(simulation_mode=simulation)
        bridge.kill(pid, device_id=device_id)
        console.print(f"[bold red]Terminated process[/bold red] [bold yellow]{pid}[/bold yellow]")
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@dynamic_app.command(name="gen", help="Generate Frida hook script for Java or native function.")
def generate_hook(
    target: str = typer.Argument(
        ...,
        help="Target method ('com.example.App#main'), class ('com.example.App'), or native symbol ('open').",
    ),
    native: bool = typer.Option(
        False,
        "--native",
        "-n",
        help="Generate native Interceptor.attach hook instead of Java hook.",
    ),
    library: str | None = typer.Option(
        None,
        "--lib",
        "-l",
        help="Native library name for native symbol (e.g. 'libc.so').",
    ),
    custom_return: str | None = typer.Option(
        None,
        "--return",
        "-r",
        help="Custom return expression to override method return value.",
    ),
    out_file: Path | None = typer.Option(
        None,
        "--out",
        "-o",
        help="Output script to file path.",
    ),
) -> None:
    try:
        if native:
            script = generate_native_hook(target, library_name=library)
        elif "#" in target:
            cls_name, meth_name = target.split("#", 1)
            script = generate_java_method_hook(
                cls_name, meth_name, custom_return=custom_return
            )
        elif "->" in target:
            cls_name, meth_name = target.split("->", 1)
            script = generate_java_method_hook(
                cls_name, meth_name, custom_return=custom_return
            )
        else:
            script = generate_java_class_hook(target)

        if out_file:
            out_file.write_text(script, encoding="utf-8")
            console.print(f"[bold green]Saved hook script to[/bold green] '{out_file}'")
        else:
            print(script)
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@dynamic_app.command(name="trace", help="Generate or run dynamic method tracer.")
def trace_pattern(
    pattern: str = typer.Argument(
        ...,
        help="Class and method pattern to trace (e.g. 'com.example.*!on*' or 'com.example.Auth*').",
    ),
    out_file: Path | None = typer.Option(
        None,
        "--out",
        "-o",
        help="Write tracer script to file.",
    ),
) -> None:
    try:
        script = generate_pattern_tracer_script(pattern)
        if out_file:
            out_file.write_text(script, encoding="utf-8")
            console.print(f"[bold green]Saved tracer script to[/bold green] '{out_file}'")
        else:
            print(script)
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@dynamic_app.command(
    name="bypass",
    help="Generate security test bypass script (SSL pinning, root, debug, emulator, or all).",
)
def bypass_command(
    module: str = typer.Argument(
        "all",
        help="Target module to bypass ('ssl', 'root', 'debug', 'emulator', or 'all').",
    ),
    out_file: Path | None = typer.Option(
        None,
        "--out",
        "-o",
        help="Output script to file path.",
    ),
) -> None:
    try:
        if module == "all":
            script = generate_combined_bypass()
        else:
            script = generate_combined_bypass([module])

        if out_file:
            out_file.write_text(script, encoding="utf-8")
            console.print(f"[bold green]Saved bypass script to[/bold green] '{out_file}'")
        else:
            print(script)
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@mem_app.command(
    name="search",
    help="Generate memory range scanning script for target string or hex pattern.",
)
def mem_search(
    pattern: str = typer.Argument(
        ..., help="Search pattern (ASCII string or hex bytes)."
    ),
    is_hex: bool = typer.Option(
        False,
        "--hex",
        help="Interpret pattern as hex bytes (e.g. '48 65 6c 6c 6f').",
    ),
    out_file: Path | None = typer.Option(
        None, "--out", "-o", help="Output script to file."
    ),
) -> None:
    try:
        script = generate_memory_search_script(pattern, is_hex=is_hex)
        if out_file:
            out_file.write_text(script, encoding="utf-8")
            console.print(
                f"[bold green]Saved memory search script to[/bold green] '{out_file}'"
            )
        else:
            print(script)
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@mem_app.command(name="dump", help="Generate memory range dumping script.")
def mem_dump(
    address: str = typer.Argument(
        ..., help="Hex base address to dump (e.g. '0x7fff0000')."
    ),
    length: int = typer.Argument(..., help="Number of bytes to dump."),
    out_file: Path | None = typer.Option(
        None, "--out", "-o", help="Output script to file."
    ),
) -> None:
    try:
        script = generate_memory_dump_script(address, length)
        if out_file:
            out_file.write_text(script, encoding="utf-8")
            console.print(
                f"[bold green]Saved memory dump script to[/bold green] '{out_file}'"
            )
        else:
            print(script)
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@dynamic_app.command(
    name="traces", help="View recorded dynamic trace events for a session."
)
def view_traces(
    session_id: str | None = typer.Option(
        None,
        "--session",
        "-s",
        help="Target session ID. Defaults to active session.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output traces in JSON format.",
    ),
) -> None:
    try:
        cfg = AndoGuardConfig()
        store = SessionStore(cfg)
        sid = session_id
        if not sid:
            active = store.get_active_session()
            if not active:
                console.print(
                    "[yellow]No active session found. Specify --session <id>[/yellow]"
                )
                raise typer.Exit(code=1)
            sid = active.id

        events = store.get_trace_events(sid)
        render_trace_events(events, as_json=json_output)
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@dynamic_app.command(
    name="replay", help="Replay recorded dynamic trace events sequentially."
)
def replay_traces(
    session_id: str = typer.Argument(
        ..., help="Session ID whose traces to replay."
    ),
    delay: float = typer.Option(
        0.0, "--delay", help="Delay between replayed events in seconds."
    ),
) -> None:
    try:
        cfg = AndoGuardConfig()
        store = SessionStore(cfg)
        events = store.get_trace_events(session_id)
        if not events:
            console.print(
                f"[yellow]No trace events recorded for session '{session_id}'.[/yellow]"
            )
            return

        console.print(
            f"[bold blue]Replaying {len(events)} events for session '{session_id}'...[/bold blue]"
        )
        for e in events:
            render_trace_event(e)
            if delay > 0:
                time.sleep(delay)
        console.print("[bold green]Trace replay finished.[/bold green]")
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
