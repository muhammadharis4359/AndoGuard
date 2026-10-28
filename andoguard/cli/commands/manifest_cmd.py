"""Command implementation for 'andoguard manifest'."""

from pathlib import Path

import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import (
    render_error,
    render_manifest,
    status_spinner,
)
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError, SessionActiveError
from andoguard.session.store import SessionStore


def show_manifest(
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
    raw: bool = typer.Option(
        False,
        "--raw",
        help="Output raw decoded AndroidManifest.xml XML text.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output structured manifest data in machine-readable JSON format.",
    ),
) -> None:
    """Decode and inspect AndroidManifest.xml metadata and security flags.

    Example:
        andoguard manifest
        andoguard manifest --raw
        andoguard manifest --json
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
            "[bold green]Decoding AndroidManifest.xml...[/bold green]",
            enabled=not json_output and not raw,
        ):
            ag = AndoGuard.resume(sid, work_dir=work_dir)
            manifest_data = ag.manifest.data()

        render_manifest(manifest_data, as_json=json_output, raw=raw)
        ag.close()
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
