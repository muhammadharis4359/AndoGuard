"""Command implementations for 'andoguard sessions' and 'andoguard resume'."""

from pathlib import Path

import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import (
    console,
    render_error,
    render_sessions,
    render_summary_card,
    status_spinner,
)
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError
from andoguard.session.store import SessionStore


def list_sessions(
    work_dir: Path | None = typer.Option(
        None,
        "--work-dir",
        help="Custom working directory for session database.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output session list in machine-readable JSON format.",
    ),
) -> None:
    """List all active and historical analysis sessions.

    Example:
        andoguard sessions
        andoguard sessions --json
    """
    try:
        cfg = AndoGuardConfig.load()
        if work_dir:
            cfg.work_dir = work_dir
            cfg.ensure_directories()

        store = SessionStore(config=cfg)
        sessions = store.list_sessions()
        render_sessions(sessions, active_id=cfg.active_session_id, as_json=json_output)
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


def resume_session(
    identifier: str = typer.Argument(
        ...,
        help="Session ID or human-readable session name to resume. Example: andoguard resume audit-v1",
    ),
    work_dir: Path | None = typer.Option(
        None,
        "--work-dir",
        help="Custom working directory for session database.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output resumed session summary in machine-readable JSON format.",
    ),
) -> None:
    """Resume a previously saved session and set it as active.

    Example:
        andoguard resume b4f8a120
        andoguard resume my-app-session
    """
    try:
        with status_spinner(
            f"[bold green]Resuming session '{identifier}'...[/bold green]",
            enabled=not json_output,
        ):
            ag = AndoGuard.resume(identifier, work_dir=work_dir)

        if json_output:
            print(ag.session_record.model_dump_json(indent=2))
        else:
            console.print(
                f"[bold green]Resumed session:[/bold green] {ag.session_record.name} ({ag.session_record.session_id})"
            )
            render_summary_card(ag.target_info, ag.session_record)

        ag.close()
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
