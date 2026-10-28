"""Command implementation for 'andoguard vulns'."""

from pathlib import Path

import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import render_error, render_vulns, status_spinner
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError, SessionActiveError
from andoguard.session.store import SessionStore


def show_vulns(
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
        help="Output vulnerability report in JSON format.",
    ),
) -> None:
    """Audit application against OWASP MASVS and MASTG security standards.

    Example:
        andoguard vulns
        andoguard vulns --json
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
            "[bold green]Running OWASP MASVS vulnerability audit...[/bold green]",
            enabled=not json_output,
        ):
            ag = AndoGuard.resume(sid, work_dir=work_dir)
            report = ag.vulns()

        render_vulns(report, as_json=json_output)
        ag.close()
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
