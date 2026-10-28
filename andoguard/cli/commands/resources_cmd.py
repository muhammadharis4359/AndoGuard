"""Command implementation for 'andoguard resources'."""

from pathlib import Path

import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import (
    render_error,
    render_resources,
    status_spinner,
)
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError, SessionActiveError
from andoguard.session.store import SessionStore


def show_resources(
    session_id: str | None = typer.Option(
        None,
        "--session",
        "-s",
        help="Session ID or name to inspect. Defaults to currently active session.",
    ),
    res_type: str | None = typer.Option(
        None,
        "--type",
        "-t",
        help="Filter resources by type (e.g. string, drawable, layout, color).",
    ),
    grep: str | None = typer.Option(
        None,
        "--grep",
        "-g",
        help="Filter resources by name or value pattern.",
    ),
    work_dir: Path | None = typer.Option(
        None,
        "--work-dir",
        help="Custom working directory for session store.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output resources in machine-readable JSON format.",
    ),
) -> None:
    """Extract and inspect Android resource table entries (resources.arsc).

    Example:
        andoguard resources
        andoguard resources --type string
        andoguard resources --grep api_key
        andoguard resources --json
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
            "[bold green]Parsing resources.arsc table...[/bold green]",
            enabled=not json_output,
        ):
            ag = AndoGuard.resume(sid, work_dir=work_dir)
            resources = ag.resources(res_type=res_type, grep=grep)

        render_resources(resources, as_json=json_output)
        ag.close()
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
