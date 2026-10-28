"""Command implementation for 'andoguard open'."""

from pathlib import Path

import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import (
    render_error,
    render_summary_card,
    status_spinner,
)
from andoguard.errors import AndoGuardError
from andoguard.models import AnalysisMode


def open_target(
    target: Path = typer.Argument(
        ...,
        help="Path to APK, DEX, ODEX, OAT, or VDEX file to inspect. Example: andoguard open sample.apk",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
    ),
    name: str | None = typer.Option(
        None,
        "--name",
        "-n",
        help="Custom human-readable session name. Example: --name audit-login",
    ),
    mode: str = typer.Option(
        "static",
        "--mode",
        "-m",
        help="Operating mode: static, dynamic, or adaptive. Example: --mode static",
    ),
    work_dir: Path | None = typer.Option(
        None,
        "--work-dir",
        help="Custom working directory for session database and extracted files.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output target metadata in machine-readable JSON format.",
    ),
) -> None:
    """Open an Android binary, create or link a persistent session, and display summary card.

    Example:
        andoguard open app-release.apk --name audit-v1 --mode static
    """
    try:
        try:
            analysis_mode = AnalysisMode(mode.lower())
        except ValueError:
            analysis_mode = AnalysisMode.STATIC

        with status_spinner(
            "[bold green]Inspecting target and initializing session...[/bold green]",
            enabled=not json_output,
        ):
            ag = AndoGuard.open(
                target_path=target,
                session_name=name,
                mode=analysis_mode,
                work_dir=work_dir,
            )

        if json_output:
            print(ag.target_info.model_dump_json(indent=2))
        else:
            render_summary_card(ag.target_info, ag.session_record)

        ag.close()
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=2) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
