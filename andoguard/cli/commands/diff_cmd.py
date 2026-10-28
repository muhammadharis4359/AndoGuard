"""Command implementation for 'andoguard diff'."""

from pathlib import Path

import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import render_diff, render_error, status_spinner
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError, SessionActiveError
from andoguard.session.store import SessionStore


def show_diff(
    other_target: str = typer.Argument(
        ...,
        help="Path to other APK binary or session name/ID to compare against.",
    ),
    session_id: str | None = typer.Option(
        None,
        "--session",
        "-s",
        help="Base session ID or name. Defaults to active session.",
    ),
    work_dir: Path | None = typer.Option(
        None,
        "--work-dir",
        help="Custom working directory for session store.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output structural diff in JSON format.",
    ),
) -> None:
    """Compare active session target against another APK or session.

    Example:
        andoguard diff path/to/v2.apk
        andoguard diff other_session_id --json
    """
    try:
        cfg_file = (work_dir / "config.json") if work_dir else None
        cfg = AndoGuardConfig.load(config_path=cfg_file)
        if work_dir:
            cfg.work_dir = work_dir
            cfg.ensure_directories()

        store = SessionStore(config=cfg)
        sid = session_id
        if not sid:
            active = store.get_active_session()
            if active:
                sid = active.session_id
            elif cfg.active_session_id:
                sid = cfg.active_session_id

        if not sid:
            raise SessionActiveError()

        with status_spinner(
            f"[bold green]Diffing against '{other_target}'...[/bold green]",
            enabled=not json_output,
        ):
            ag = AndoGuard.resume(sid, work_dir=work_dir)
            result = ag.diff(other_target)

        render_diff(result, as_json=json_output)
        ag.close()
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
