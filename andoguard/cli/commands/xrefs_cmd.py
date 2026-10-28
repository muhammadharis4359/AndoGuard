"""Command implementation for 'andoguard xrefs'."""

from pathlib import Path

import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import render_error, render_xrefs, status_spinner
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError, SessionActiveError
from andoguard.session.store import SessionStore


def show_xrefs(
    target: str = typer.Argument(
        ...,
        help="Target method, class, or string literal (e.g. 'com.example.App#main' or 'Lcom/example/App;' or 'api_key').",
    ),
    to_only: bool = typer.Option(
        False,
        "--to",
        help="Show only incoming references (callers of this target).",
    ),
    from_only: bool = typer.Option(
        False,
        "--from",
        help="Show only outgoing references (calls made by this target).",
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
        help="Output cross-references in JSON format.",
    ),
) -> None:
    """Find cross-references (callers, callees, string references) for a target symbol.

    Example:
        andoguard xrefs "com.example.MainActivity#onCreate"
        andoguard xrefs "com.example.MainActivity#onCreate" --to
        andoguard xrefs "https://api.example.com"
        andoguard xrefs "Lcom/example/MainActivity;" --json
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

        direction = "both"
        if to_only and not from_only:
            direction = "to"
        elif from_only and not to_only:
            direction = "from"

        with status_spinner(
            f"[bold green]Finding cross-references for '{target}'...[/bold green]",
            enabled=not json_output,
        ):
            ag = AndoGuard.resume(sid, work_dir=work_dir)
            result = ag.xrefs(target, direction=direction)

        render_xrefs(result, as_json=json_output)
        ag.close()
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
