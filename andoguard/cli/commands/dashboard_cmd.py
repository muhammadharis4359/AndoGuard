"""CLI command to launch AndoGuard modern web dashboard."""

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from andoguard.dashboard.server import start_dashboard_server

console = Console()


def dashboard_cmd(
    target: Path | None = typer.Argument(
        None,
        help="Optional path to APK, DEX, or session target to open on launch.",
        exists=True,
        readable=True,
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        "-h",
        help="Host interface to bind the web dashboard server to.",
    ),
    port: int = typer.Option(
        8080,
        "--port",
        "-p",
        help="Port number for the web dashboard server.",
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="Do not automatically open default web browser upon starting.",
    ),
) -> None:
    """Launch AndoGuard modern interactive cybersecurity dashboard."""
    console.print(
        Panel(
            f"[bold cyan]AndoGuard[/bold cyan] [bold green]Modern Web Dashboard[/bold green]\n"
            f"Binding to [bold yellow]http://{host}:{port}[/bold yellow]\n"
            f"Target: [bold magenta]{target or 'Default Showcase Target'}[/bold magenta]\n"
            f"[dim]Press Ctrl+C to stop the dashboard server[/dim]",
            title="[bold blue]🛡️ AndoGuard Command Center[/bold blue]",
            border_style="cyan",
        )
    )
    start_dashboard_server(
        host=host,
        port=port,
        open_browser=not no_browser,
        target=target,
    )
