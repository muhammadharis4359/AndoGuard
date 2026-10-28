"""CLI subcommands for dynamic instrumentation ('andoguard dynamic ...')."""

import json
from pathlib import Path

import typer

from andoguard.adapters.frida_bridge import FridaBridge
from andoguard.cli.render import (
    console,
    render_devices,
    render_error,
    render_processes,
    status_spinner,
)
from andoguard.dynamic.generator import (
    generate_java_class_hook,
    generate_java_method_hook,
    generate_native_hook,
)
from andoguard.dynamic.tracer import generate_pattern_tracer_script
from andoguard.errors import AndoGuardError

dynamic_app = typer.Typer(
    name="dynamic",
    help="Dynamic instrumentation, Frida runtime hooking, and device interaction.",
    no_args_is_help=True,
)


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
