"""Command implementation for 'andoguard info'."""

from pathlib import Path

import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import (
    render_error,
    render_info,
    status_spinner,
)
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError, SessionActiveError
from andoguard.session.store import SessionStore


def show_info(
    session_id: str | None = typer.Option(
        None,
        "--session",
        "-s",
        help="Session ID or name to inspect. Defaults to currently active session.",
    ),
    work_dir: Path | None = typer.Option(
        None,
        "--work-dir",
        help="Custom working directory for session store.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output target metadata in machine-readable JSON format.",
    ),
) -> None:
    """Display comprehensive metadata for the active or specified session target.

    Example:
        andoguard info
        andoguard info --json
        andoguard info --session audit-login
    """
    try:
        cfg = AndoGuardConfig.load()
        if work_dir:
            cfg.work_dir = work_dir
            cfg.ensure_directories()

        store = SessionStore(config=cfg)
        sid = session_id or cfg.active_session_id
        if not sid:
            active = store.get_active_session()
            if active:
                sid = active.session_id

        if not sid:
            raise SessionActiveError()

        with status_spinner(
            "[bold green]Loading target information...[/bold green]",
            enabled=not json_output,
        ):
            ag = AndoGuard.resume(sid, work_dir=work_dir)
            info = ag.info()

        render_info(info, as_json=json_output)
        ag.close()
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
