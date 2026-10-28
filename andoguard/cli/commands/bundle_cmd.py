"""CLI commands for session archive export and import ('andoguard export', 'andoguard import')."""

from pathlib import Path

import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import console, render_error, status_spinner
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError
from andoguard.session.store import SessionStore


def export_bundle_cmd(
    session_id: str | None = typer.Argument(
        None,
        help="Session ID to export. Defaults to currently active session.",
    ),
    out_file: Path | None = typer.Option(
        None,
        "--out",
        "-o",
        help="Output .agguard bundle file path.",
    ),
) -> None:
    """Export complete session, findings, and artifacts into verified .agguard bundle."""
    try:
        cfg = AndoGuardConfig.load()
        store = SessionStore(cfg)
        sid = session_id or (active.session_id if (active := store.get_active_session()) else None)

        if not sid:
            console.print("[yellow]No active session found. Specify <session_id>[/yellow]")
            raise typer.Exit(code=1)

        with AndoGuard.resume(sid) as ag:
            with status_spinner("Packaging session bundle...", enabled=True):
                bundle_path = ag.export_bundle(out_path=out_file)

        console.print(f"[bold green]Successfully exported session bundle to[/bold green] '{bundle_path}'")
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


def import_bundle_cmd(
    bundle_file: Path = typer.Argument(
        ...,
        help="Path to .agguard session archive to import.",
    ),
) -> None:
    """Import and verify an .agguard session archive into local database."""
    try:
        with status_spinner(f"Verifying and importing '{bundle_file.name}'...", enabled=True):
            session_rec = AndoGuard.import_bundle(bundle_file)

        console.print(
            f"[bold green]Successfully imported session[/bold green] [bold cyan]'{session_rec.name}'[/bold cyan] "
            f"([bold yellow]{session_rec.session_id}[/bold yellow])"
        )
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
