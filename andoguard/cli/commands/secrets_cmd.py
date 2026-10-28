"""Command implementation for 'andoguard secrets'."""

from pathlib import Path

import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import render_error, render_secrets, status_spinner
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError, SessionActiveError
from andoguard.session.store import SessionStore


def show_secrets(
    min_entropy: float = typer.Option(
        3.8,
        "--min-entropy",
        "-e",
        help="Minimum Shannon entropy threshold for high-entropy strings.",
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
        help="Output secret findings in JSON format.",
    ),
) -> None:
    """Scan bytecode and resources for credentials, API keys, tokens, and high-entropy secrets.

    Example:
        andoguard secrets
        andoguard secrets --min-entropy 4.0
        andoguard secrets --json
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
            "[bold green]Scanning for secrets and high-entropy tokens...[/bold green]",
            enabled=not json_output,
        ):
            ag = AndoGuard.resume(sid, work_dir=work_dir)
            findings = ag.secrets(min_entropy=min_entropy)

        render_secrets(findings, as_json=json_output)
        ag.close()
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
