"""Command implementation for 'andoguard strings'."""

from pathlib import Path

import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import (
    render_error,
    render_strings,
    status_spinner,
)
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError, SessionActiveError
from andoguard.session.store import SessionStore


def show_strings(
    session_id: str | None = typer.Option(
        None,
        "--session",
        "-s",
        help="Session ID or name to inspect. Defaults to currently active session.",
    ),
    min_len: int = typer.Option(
        4,
        "--min-len",
        "-m",
        help="Minimum string character length filter.",
    ),
    entropy: bool = typer.Option(
        False,
        "--entropy",
        "-e",
        help="Calculate Shannon entropy and sort strings by highest entropy (useful for secrets).",
    ),
    grep: str | None = typer.Option(
        None,
        "--grep",
        "-g",
        help="Filter string literals by search keyword or pattern.",
    ),
    work_dir: Path | None = typer.Option(
        None,
        "--work-dir",
        help="Custom working directory for session store.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output string items in machine-readable JSON format.",
    ),
) -> None:
    """Extract and analyze string literals from target DEX and resources.

    Example:
        andoguard strings
        andoguard strings --min-len 8
        andoguard strings --entropy
        andoguard strings --grep "http"
        andoguard strings --json
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
            "[bold green]Extracting strings from target...[/bold green]",
            enabled=not json_output,
        ):
            ag = AndoGuard.resume(sid, work_dir=work_dir)
            items = ag.string_items(min_len=min_len, entropy=entropy)
            if grep:
                pattern = grep.lower()
                items = [it for it in items if pattern in it.value.lower()]

        render_strings(items, as_json=json_output)
        ag.close()
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
