"""Main CLI entrypoint for AndoGuard."""

import sys

import typer
from rich.console import Console

from andoguard import __version__
from andoguard.cli.commands import (
    list_sessions,
    open_target,
    resume_session,
    show_certs,
    show_files,
    show_info,
    show_manifest,
    show_resources,
    show_strings,
)
from andoguard.cli.render import render_notice

app = typer.Typer(
    name="andoguard",
    help="AndoGuard: Production-Grade Android Reverse Engineering & Security Testing Toolkit.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


def version_callback(value: bool) -> None:
    """Print version information and authorized testing notice."""
    if value:
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        console.print(
            f"[bold cyan]AndoGuard[/bold cyan] version [bold green]{__version__}[/bold green] (Python {py_ver})"
        )
        render_notice()
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version information and authorized testing notice.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """AndoGuard — Authorized Android Reverse Engineering & Security Assessment Toolkit."""


# Register CLI commands
app.command(
    name="open",
    help="Open an Android binary, start/link a session, and inspect target.",
)(open_target)
app.command(
    name="info", help="Display metadata for the active or selected session target."
)(show_info)
app.command(name="sessions", help="List all historical and active analysis sessions.")(
    list_sessions
)
app.command(name="resume", help="Resume a previously saved session and set it active.")(
    resume_session
)
app.command(
    name="manifest",
    help="Decode and inspect AndroidManifest.xml metadata and security flags.",
)(show_manifest)
app.command(
    name="resources",
    help="Extract and inspect Android resource table entries (resources.arsc).",
)(show_resources)
app.command(
    name="files",
    help="Browse APK container file tree, native libraries, and assets.",
)(show_files)
app.command(
    name="certs",
    help="Inspect APK signature schemes (v1, v2, v3) and X.509 certificate fingerprints.",
)(show_certs)
app.command(
    name="strings",
    help="Extract and analyze string literals from target DEX and resources.",
)(show_strings)


if __name__ == "__main__":
    app()
