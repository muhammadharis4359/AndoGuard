"""CLI command for generating multi-format security reports ('andoguard report')."""

from pathlib import Path

import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import console, render_error, status_spinner
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError
from andoguard.session.store import SessionStore


def generate_report_cmd(
    format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Report format: 'markdown' (default), 'html', or 'json'.",
    ),
    out_file: Path | None = typer.Option(
        None,
        "--out",
        "-o",
        help="Write generated report to file path.",
    ),
    session_id: str | None = typer.Option(
        None,
        "--session",
        "-s",
        help="Target session ID. Defaults to active session.",
    ),
) -> None:
    """Generate comprehensive security assessment report."""
    try:
        cfg = AndoGuardConfig.load()
        store = SessionStore(cfg)
        sid = session_id or (active.session_id if (active := store.get_active_session()) else None)

        if not sid:
            console.print("[yellow]No active session found. Specify --session <id>[/yellow]")
            raise typer.Exit(code=1)

        with AndoGuard.resume(sid) as ag:
            with status_spinner(f"Generating {format.upper()} assessment report...", enabled=out_file is not None):
                report_content = ag.generate_report(format=format)

        if out_file:
            out_file.write_text(report_content, encoding="utf-8")
            console.print(f"[bold green]Saved {format.upper()} report to[/bold green] '{out_file}'")
        else:
            print(report_content)
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
