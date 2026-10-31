"""Main CLI entrypoint for AndoGuard."""

import sys

import typer
from rich.console import Console

from andoguard import __version__
from andoguard.cli.commands import (
    adaptive_app,
    ai_app,
    dashboard_cmd,
    dynamic_app,
    export_bundle_cmd,
    generate_report_cmd,
    import_bundle_cmd,
    list_sessions,
    open_target,
    resume_session,
    search_target,
    show_certs,
    show_classes,
    show_code,
    show_diff,
    show_disasm,
    show_files,
    show_info,
    show_manifest,
    show_methods,
    show_native,
    show_resources,
    show_secrets,
    show_strings,
    show_vulns,
    show_xrefs,
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
    name="dashboard",
    help="Launch interactive modern web dashboard for presentation and analysis.",
)(dashboard_cmd)
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
app.command(
    name="classes",
    help="List and filter classes defined in bytecode.",
)(show_classes)
app.command(
    name="methods",
    help="List methods defined for a class.",
)(show_methods)
app.command(
    name="disasm",
    help="Disassemble Dalvik bytecode with optional Control Flow Graph (CFG).",
)(show_disasm)
app.command(
    name="code",
    help="Decompile Dalvik bytecode to Java or Dalvik source representation.",
)(show_code)
app.command(
    name="xrefs",
    help="Find cross-references (callers, callees, strings) for a target symbol.",
)(show_xrefs)
app.command(
    name="search",
    help="Full-text search indexed bytecode, strings, components, and resources.",
)(search_target)
app.command(
    name="secrets",
    help="Scan bytecode and resources for API keys, credentials, and high-entropy secrets.",
)(show_secrets)
app.command(
    name="vulns",
    help="Audit target against OWASP MASVS and MASTG security standards.",
)(show_vulns)
app.command(
    name="native",
    help="Inspect native ELF shared libraries (.so), architectures, dependencies, and JNI symbols.",
)(show_native)
app.command(
    name="diff",
    help="Compare active session target against another APK or session.",
)(show_diff)
app.command(
    name="report",
    help="Generate comprehensive security assessment report (Markdown, HTML, or JSON).",
)(generate_report_cmd)
app.command(
    name="export",
    help="Export session, findings, and artifacts into verified .agguard bundle.",
)(export_bundle_cmd)
app.command(
    name="import",
    help="Import and verify an .agguard session archive into local database.",
)(import_bundle_cmd)
app.add_typer(dynamic_app, name="dynamic")
app.add_typer(ai_app, name="ai")
app.add_typer(adaptive_app, name="adaptive")


if __name__ == "__main__":
    app()
