"""Rich terminal rendering utilities for AndoGuard CLI."""

import contextlib
import json
from collections.abc import Generator

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from andoguard.errors import AndoGuardError
from andoguard.models import (
    ApkFileEntry,
    CodeResult,
    DisasmResult,
    ManifestData,
    ResourceEntry,
    SessionRecord,
    SignatureReport,
    StringItem,
    TargetInfo,
)

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


def render_manifest(
    data: ManifestData, as_json: bool = False, raw: bool = False
) -> None:
    """Render AndroidManifest.xml details or raw XML."""
    if raw:
        if data.raw_xml:
            print(data.raw_xml)
        else:
            console.print("[yellow]No raw XML available in target.[/yellow]")
        return

    if as_json:
        print(json.dumps(data.model_dump(), indent=2))
        return

    # Overview table
    table = Table(
        title="Manifest Overview", show_header=True, header_style="bold magenta"
    )
    table.add_column("Property", style="cyan", width=24)
    table.add_column("Value", style="white")

    table.add_row("Package", data.package_name or "N/A")
    table.add_row(
        "Version Code",
        str(data.version_code) if data.version_code is not None else "N/A",
    )
    table.add_row("Version Name", data.version_name or "N/A")
    table.add_row(
        "Min SDK",
        str(data.min_sdk_version) if data.min_sdk_version is not None else "N/A",
    )
    table.add_row(
        "Target SDK",
        str(data.target_sdk_version) if data.target_sdk_version is not None else "N/A",
    )

    # Security flags
    sec = data.security_flags
    dbg_style = "bold red" if sec.debuggable else "green"
    backup_style = "yellow" if sec.allow_backup else "green"
    clear_style = "bold yellow" if sec.uses_cleartext_traffic else "green"

    table.add_row("Debuggable", f"[{dbg_style}]{sec.debuggable}[/{dbg_style}]")
    table.add_row(
        "Allow Backup", f"[{backup_style}]{sec.allow_backup}[/{backup_style}]"
    )
    table.add_row(
        "Cleartext Traffic",
        f"[{clear_style}]{sec.uses_cleartext_traffic}[/{clear_style}]",
    )
    table.add_row("Network Security Config", sec.network_security_config or "Default")
    table.add_row("Test Only", str(sec.test_only))
    console.print(table)

    # Permissions table
    if data.permissions:
        p_table = Table(
            title=f"Requested Permissions ({len(data.permissions)})",
            show_header=True,
            header_style="bold yellow",
        )
        p_table.add_column("Permission Name", style="white")
        for p in sorted(data.permissions):
            p_table.add_row(p)
        console.print(p_table)

    # Exported components table
    exported_comps = [c for c in data.components if c.exported]
    if exported_comps:
        c_table = Table(
            title=f"Exported Components ({len(exported_comps)})",
            show_header=True,
            header_style="bold red",
        )
        c_table.add_column("Type", style="cyan", width=12)
        c_table.add_column("Name", style="white")
        c_table.add_column("Permission Guard", style="yellow")
        for c in exported_comps:
            c_table.add_row(
                c.component_type.upper(),
                c.name,
                c.permission or "[bold red]None (Public)[/bold red]",
            )
        console.print(c_table)


def render_resources(resources: list[ResourceEntry], as_json: bool = False) -> None:
    """Render resource table entries."""
    if as_json:
        payload = [r.model_dump() for r in resources]
        print(json.dumps(payload, indent=2))
        return

    if not resources:
        console.print("[yellow]No matching resources found.[/yellow]")
        return

    table = Table(
        title=f"Android Resources ({len(resources)})",
        show_header=True,
        header_style="bold blue",
    )
    table.add_column("Resource ID", style="dim", width=12)
    table.add_column("Type", style="cyan", width=14)
    table.add_column("Name", style="white", min_width=20)
    table.add_column("Value / Resolved", style="green")

    for r in resources[:200]:  # Cap CLI view to first 200 items
        table.add_row(r.res_id, r.res_type, r.name, r.value or "-")

    console.print(table)
    if len(resources) > 200:
        console.print(
            f"[dim]... and {len(resources) - 200} more items (use --json for complete output).[/dim]"
        )


def render_files(files: list[ApkFileEntry], as_json: bool = False) -> None:
    """Render APK file tree."""
    if as_json:
        payload = [f.model_dump() for f in files]
        print(json.dumps(payload, indent=2))
        return

    if not files:
        console.print("[yellow]No files found.[/yellow]")
        return

    table = Table(
        title=f"APK Files ({len(files)})", show_header=True, header_style="bold cyan"
    )
    table.add_column("Type", style="yellow", width=8)
    table.add_column("Path", style="white")
    table.add_column("Size", style="cyan", justify="right", width=12)
    table.add_column("CRC32", style="dim", width=10)

    for f in files[:200]:
        t_label = (
            "SO"
            if f.is_so
            else ("ASSET" if f.is_asset else ("DEX" if f.is_dex else "FILE"))
        )
        crc_str = f"{f.crc:08x}" if f.crc is not None else "-"
        table.add_row(t_label, f.path, format_bytes(f.size), crc_str)

    console.print(table)
    if len(files) > 200:
        console.print(
            f"[dim]... and {len(files) - 200} more files (use --json for complete output).[/dim]"
        )


def render_signatures(report: SignatureReport, as_json: bool = False) -> None:
    """Render signature schemes and X.509 certificate fingerprints."""
    if as_json:
        print(json.dumps(report.model_dump(), indent=2))
        return

    table = Table(
        title="APK Signatures & Certificates",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Property", style="cyan", width=22)
    table.add_column("Status / Value", style="white")

    table.add_row(
        "Signed Status",
        "[green]Signed[/green]"
        if report.is_signed
        else "[bold red]Unsigned[/bold red]",
    )
    table.add_row(
        "Scheme v1 (JAR)",
        "[green]Yes[/green]" if report.v1_signature else "[dim]No[/dim]",
    )
    table.add_row(
        "Scheme v2 (APK)",
        "[green]Yes[/green]" if report.v2_signature else "[dim]No[/dim]",
    )
    table.add_row(
        "Scheme v3 (Key Rotation)",
        "[green]Yes[/green]" if report.v3_signature else "[dim]No[/dim]",
    )
    table.add_row("Certificates Count", str(len(report.certificates)))

    console.print(table)

    for idx, c in enumerate(report.certificates, start=1):
        c_table = Table(
            title=f"Certificate #{idx}", show_header=True, header_style="bold green"
        )
        c_table.add_column("Field", style="cyan", width=20)
        c_table.add_column("Details", style="white")

        c_table.add_row("Subject", c.subject)
        c_table.add_row("Issuer", c.issuer)
        c_table.add_row("SHA-256 Fingerprint", c.sha256_fingerprint)
        c_table.add_row("SHA-1 Fingerprint", c.sha1_fingerprint)
        c_table.add_row("Valid From", c.valid_from)
        c_table.add_row("Valid To", c.valid_to)
        c_table.add_row("Algorithm", c.signature_algorithm or "Unknown")
        c_table.add_row(
            "Self-Signed", "[yellow]Yes[/yellow]" if c.is_self_signed else "No"
        )
        console.print(c_table)


def render_strings(strings: list[StringItem], as_json: bool = False) -> None:
    """Render string table with entropy."""
    if as_json:
        payload = [s.model_dump() for s in strings]
        print(json.dumps(payload, indent=2))
        return

    if not strings:
        console.print("[yellow]No strings found matching criteria.[/yellow]")
        return

    table = Table(
        title=f"Strings ({len(strings)})", show_header=True, header_style="bold blue"
    )
    table.add_column("Entropy", style="magenta", justify="right", width=10)
    table.add_column("Length", style="dim", justify="right", width=8)
    table.add_column("Source", style="cyan", width=8)
    table.add_column("Value", style="white")

    for s in strings[:150]:
        val_display = s.value[:80] + ("..." if len(s.value) > 80 else "")
        table.add_row(f"{s.entropy:.2f}", str(s.length), s.source, val_display)

    console.print(table)
    if len(strings) > 150:
        console.print(
            f"[dim]... and {len(strings) - 150} more strings (use --json for complete output).[/dim]"
        )


def render_classes(classes: list[str], as_json: bool = False) -> None:
    """Render list of classes."""
    if as_json:
        print(json.dumps(classes, indent=2))
        return

    if not classes:
        console.print("[yellow]No classes found.[/yellow]")
        return

    table = Table(
        title=f"Classes ({len(classes)})",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Class Name", style="white")
    for c in classes[:250]:
        table.add_row(c)
    console.print(table)
    if len(classes) > 250:
        console.print(
            f"[dim]... and {len(classes) - 250} more classes (use --json for complete list).[/dim]"
        )


def render_methods(methods: list[str], class_name: str, as_json: bool = False) -> None:
    """Render list of methods for a class."""
    if as_json:
        print(json.dumps({"class": class_name, "methods": methods}, indent=2))
        return

    if not methods:
        console.print(f"[yellow]No methods found for class {class_name}.[/yellow]")
        return

    table = Table(
        title=f"Methods in {class_name} ({len(methods)})",
        show_header=True,
        header_style="bold yellow",
    )
    table.add_column("Method Signature", style="white")
    for m in methods:
        table.add_row(m)
    console.print(table)


def render_disasm(result: DisasmResult, as_json: bool = False) -> None:
    """Render Dalvik bytecode disassembly."""
    if as_json:
        print(json.dumps(result.model_dump(), indent=2))
        return

    console.print(f"[bold cyan]Disassembly for {result.target}:[/bold cyan]")
    code_text = "\n".join(result.instructions)
    syntax = Syntax(code_text, "smali", theme="monokai", line_numbers=True)
    console.print(syntax)

    if result.cfg:
        console.print("\n[bold magenta]Control Flow Graph (CFG) Blocks:[/bold magenta]")
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Block", style="cyan")
        table.add_column("Range", style="dim")
        table.add_column("Instructions", style="white")
        table.add_column("Successors", style="green")
        for b in result.cfg.blocks:
            ins_summary = f"{len(b.instructions)} insns"
            table.add_row(
                b.name,
                f"0x{b.start:x}-0x{b.end:x}",
                ins_summary,
                ", ".join(b.children) or "exit",
            )
        console.print(table)
        console.print("\n[dim]DOT Graph specification:[/dim]")
        console.print(Syntax(result.cfg.dot, "dot", theme="monokai"))


def render_code(result: CodeResult, as_json: bool = False) -> None:
    """Render decompiled or disassembled code."""
    if as_json:
        print(json.dumps(result.model_dump(), indent=2))
        return

    console.print(
        f"[bold green]Code ({result.language}) for {result.target}:[/bold green]"
    )
    syntax = Syntax(
        result.source,
        "java" if result.language.lower() == "java" else "smali",
        theme="monokai",
        line_numbers=True,
    )
    console.print(syntax)

    if result.cfg:
        console.print("\n[bold magenta]Control Flow Graph (CFG) Blocks:[/bold magenta]")
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Block", style="cyan")
        table.add_column("Range", style="dim")
        table.add_column("Successors", style="green")
        for b in result.cfg.blocks:
            table.add_row(
                b.name, f"0x{b.start:x}-0x{b.end:x}", ", ".join(b.children) or "exit"
            )
        console.print(table)
        console.print("\n[dim]DOT Graph specification:[/dim]")
        console.print(Syntax(result.cfg.dot, "dot", theme="monokai"))
