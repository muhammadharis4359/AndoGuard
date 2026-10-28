"""Rich terminal rendering utilities for AndoGuard CLI."""

import contextlib
import json
from collections.abc import Generator

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from andoguard.errors import AndoGuardError
from andoguard.models import SessionRecord, TargetInfo

console = Console()
error_console = Console(stderr=True)


@contextlib.contextmanager
def status_spinner(message: str, enabled: bool = True) -> Generator[None, None, None]:
    """Show a status spinner only in interactive terminals when enabled."""
    if enabled and console.is_terminal:
        with console.status(message):
            yield
    else:
        yield


def format_bytes(size: int) -> str:
    """Format byte counts into human-readable strings."""
    sz = float(size)
    for unit in ["B", "KB", "MB", "GB"]:
        if sz < 1024.0:
            return f"{sz:3.1f} {unit}"
        sz /= 1024.0
    return f"{sz:.1f} TB"


def render_notice() -> None:
    """Render authorized testing notice banner."""
    notice = Text(
        "NOTICE: FOR AUTHORIZED SECURITY TESTING AND REVERSE ENGINEERING ONLY\n"
        "Unauthorized access to devices or applications is strictly prohibited.",
        style="bold yellow",
        justify="center",
    )
    console.print(Panel(notice, border_style="yellow"))


def render_summary_card(info: TargetInfo, session: SessionRecord) -> None:
    """Render high-level summary card when target is opened."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan", justify="right")
    table.add_column(style="white")

    table.add_row("Session ID:", session.session_id)
    table.add_row("Session Name:", session.name)
    table.add_row("Mode:", session.mode.value)
    table.add_row("Target File:", info.target_path)
    table.add_row("Format:", info.target_type.value.upper())
    table.add_row("Size:", format_bytes(info.file_size))
    table.add_row("SHA-256:", info.sha256)

    if info.package_name:
        table.add_row("Package:", info.package_name)
    if info.version_name:
        table.add_row("Version:", f"{info.version_name} (code: {info.version_code})")
    if info.target_sdk_version:
        table.add_row("Target SDK:", str(info.target_sdk_version))
    if info.main_activity:
        table.add_row("Main Activity:", info.main_activity)

    stats = (
        f"DEX: {info.dex_count} | "
        f"Permissions: {info.permissions_count} | "
        f"Activities: {info.activities_count} | "
        f"Services: {info.services_count} | "
        f"Receivers: {info.receivers_count} | "
        f"Providers: {info.providers_count}"
    )
    table.add_row("Components:", stats)

    panel = Panel(
        table,
        title="[bold green]AndoGuard — Target Summary[/bold green]",
        border_style="green",
    )
    console.print(panel)


def render_info(info: TargetInfo, as_json: bool = False) -> None:
    """Render target info in human-readable table or machine-readable JSON."""
    if as_json:
        print(json.dumps(info.model_dump(), indent=2))
        return

    table = Table(
        title="Target Information", show_header=True, header_style="bold magenta"
    )
    table.add_column("Property", style="cyan", width=22)
    table.add_column("Value", style="white")

    table.add_row("Target Path", info.target_path)
    table.add_row("Target Type", info.target_type.value.upper())
    table.add_row(
        "File Size", f"{info.file_size} bytes ({format_bytes(info.file_size)})"
    )
    table.add_row("MD5", info.md5)
    table.add_row("SHA-1", info.sha1)
    table.add_row("SHA-256", info.sha256)

    if info.package_name:
        table.add_row("Package Name", info.package_name)
    if info.app_name:
        table.add_row("App Name", info.app_name)
    if info.version_name:
        table.add_row("Version Name", info.version_name)
    if info.version_code:
        table.add_row("Version Code", str(info.version_code))
    if info.min_sdk_version:
        table.add_row("Min SDK", str(info.min_sdk_version))
    if info.target_sdk_version:
        table.add_row("Target SDK", str(info.target_sdk_version))
    if info.main_activity:
        table.add_row("Main Activity", info.main_activity)

    table.add_row("DEX Count", str(info.dex_count))
    table.add_row("Permissions Count", str(info.permissions_count))
    table.add_row("Activities Count", str(info.activities_count))
    table.add_row("Services Count", str(info.services_count))
    table.add_row("Receivers Count", str(info.receivers_count))
    table.add_row("Providers Count", str(info.providers_count))

    console.print(table)


def render_sessions(
    sessions: list[SessionRecord],
    active_id: str | None = None,
    as_json: bool = False,
) -> None:
    """Render active and past sessions."""
    if as_json:
        payload = [s.model_dump() for s in sessions]
        print(json.dumps(payload, indent=2))
        return

    if not sessions:
        console.print(
            "[yellow]No sessions found. Run 'andoguard open <file>' to begin.[/yellow]"
        )
        return

    table = Table(
        title="AndoGuard Sessions", show_header=True, header_style="bold blue"
    )
    table.add_column("Active", justify="center", width=6)
    table.add_column("ID", style="bold cyan", width=10)
    table.add_column("Name", style="white", min_width=12)
    table.add_column("Mode", style="green", width=8)
    table.add_column("Target SHA", style="dim", width=12)
    table.add_column("Updated", style="dim", width=16)

    for s in sessions:
        is_active = "*" if s.session_id == active_id else ""
        sha_short = f"{s.target_sha256[:8]}..." if s.target_sha256 else "-"
        table.add_row(
            "[bold green]*[/bold green]" if is_active else "",
            s.session_id,
            s.name,
            s.mode.value,
            sha_short,
            s.updated_at[:16].replace("T", " "),
        )

    console.print(table)


def render_error(exc: Exception) -> None:
    """Render actionable error panel without raw tracebacks for expected failures."""
    if isinstance(exc, AndoGuardError):
        msg = f"[bold red]Error:[/bold red] {exc.message}"
        if exc.remediation:
            msg += f"\n\n[bold yellow]Remediation:[/bold yellow] {exc.remediation}"
        error_console.print(Panel(msg, title="AndoGuard Failure", border_style="red"))
    else:
        error_console.print(f"[bold red]Unexpected Error:[/bold red] {exc}")
