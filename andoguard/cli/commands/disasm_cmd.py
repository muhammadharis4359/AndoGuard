"""Command implementation for 'andoguard disasm'."""

from pathlib import Path

import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import (
    render_disasm,
    render_error,
    status_spinner,
)
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError, SessionActiveError
from andoguard.session.store import SessionStore


def show_disasm(
    target: str = typer.Argument(
        ...,
        help="Class or method target (e.g. 'com.example.MainActivity#onCreate' or 'Lcom/example/MainActivity;').",
    ),
    cfg: bool = typer.Option(
        False,
        "--cfg",
        help="Generate Control Flow Graph (CFG) basic blocks and DOT graph representation.",
    ),
    session_id: str | None = typer.Option(
        None,
        "--session",
        "-s",
        help="Session ID or name to inspect. Defaults to active session.",
    ),
    work_dir: Path | None = typer.Option(
        None,
        "--work-dir",
        help="Custom working directory for session store.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output disassembly and CFG in JSON format.",
    ),
) -> None:
    """Disassemble Dalvik bytecode for a target class or specific method.

    Example:
        andoguard disasm "com.example.MainActivity#onCreate"
        andoguard disasm "com.example.MainActivity#onCreate" --cfg
        andoguard disasm "Lcom/example/MainActivity;" --json
    """
    try:
        cfg_file = (work_dir / "config.json") if work_dir else None
        cfg_settings = AndoGuardConfig.load(config_path=cfg_file)
        if work_dir:
            cfg_settings.work_dir = work_dir
            cfg_settings.ensure_directories()

        store = SessionStore(config=cfg_settings)
        sid = session_id
        if not sid:
            active = store.get_active_session()
            if active:
                sid = active.session_id
            elif cfg_settings.active_session_id:
                sid = cfg_settings.active_session_id

        if not sid:
            raise SessionActiveError()

        class_name = target
        method_name = None
        if "#" in target:
            class_name, method_name = target.split("#", 1)
        elif "->" in target:
            class_name, method_name = target.split("->", 1)

        with status_spinner(
            f"[bold green]Disassembling bytecode for {target}...[/bold green]",
            enabled=not json_output,
        ):
            ag = AndoGuard.resume(sid, work_dir=work_dir)
            result = ag.disassemble_method(class_name, method_name=method_name, cfg=cfg)

        render_disasm(result, as_json=json_output)
        ag.close()
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
