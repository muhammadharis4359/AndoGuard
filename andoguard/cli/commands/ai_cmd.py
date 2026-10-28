"""CLI subcommands for AI reasoning, code explanation, and vulnerability triage."""

import json
from pathlib import Path

import typer

from andoguard.ai.provider import list_ai_providers
from andoguard.api import AndoGuard
from andoguard.cli.render import (
    console,
    render_ai_doctor,
    render_ai_panel,
    render_error,
    status_spinner,
)
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError
from andoguard.session.store import SessionStore

ai_app = typer.Typer(
    name="ai",
    help="AI reasoning, code explanation, and automated security triage.",
    no_args_is_help=True,
)


@ai_app.command(name="doctor", help="Check availability and health of configured AI providers.")
def ai_doctor(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output health report in JSON format.",
    ),
) -> None:
    try:
        cfg = AndoGuardConfig.load()
        with status_spinner("Checking AI provider health...", enabled=not json_output):
            providers = list_ai_providers(cfg)
        render_ai_doctor(providers, as_json=json_output)
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@ai_app.command(name="ask", help="Ask AI security questions about active target session.")
def ai_ask(
    question: str = typer.Argument(..., help="Security or reverse engineering question to ask."),
    session_id: str | None = typer.Option(
        None,
        "--session",
        "-s",
        help="Session ID. Defaults to active session.",
    ),
    provider: str | None = typer.Option(
        None,
        "--provider",
        "-p",
        help="AI provider override ('gemini', 'openai', 'anthropic', 'ollama', 'mock').",
    ),
    context: str | None = typer.Option(
        None,
        "--context",
        "-c",
        help="Optional additional code or log context to supply.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output response as JSON.",
    ),
) -> None:
    try:
        cfg = AndoGuardConfig.load()
        store = SessionStore(cfg)
        sid = session_id or (active.session_id if (active := store.get_active_session()) else None)

        if not sid:
            console.print("[yellow]No active session found. Specify --session <id>[/yellow]")
            raise typer.Exit(code=1)

        with AndoGuard.resume(sid) as ag:
            with status_spinner("Querying AI model...", enabled=not json_output):
                answer = ag.ai_ask(question, context=context, provider=provider)

        if json_output:
            print(json.dumps({"question": question, "answer": answer}, indent=2))
        else:
            render_ai_panel(answer, title="AndoGuard AI Response")
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@ai_app.command(name="explain", help="De-obfuscate and explain a target class or method using AI.")
def ai_explain(
    target: str = typer.Argument(
        ...,
        help="Target class ('com.example.App') or method ('com.example.App#main').",
    ),
    session_id: str | None = typer.Option(
        None,
        "--session",
        "-s",
        help="Session ID. Defaults to active session.",
    ),
    provider: str | None = typer.Option(
        None,
        "--provider",
        "-p",
        help="AI provider override.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output explanation as JSON.",
    ),
) -> None:
    try:
        cfg = AndoGuardConfig.load()
        store = SessionStore(cfg)
        sid = session_id or (active.session_id if (active := store.get_active_session()) else None)

        if not sid:
            console.print("[yellow]No active session found. Specify --session <id>[/yellow]")
            raise typer.Exit(code=1)

        with AndoGuard.resume(sid) as ag:
            with status_spinner(f"Analyzing '{target}' with AI...", enabled=not json_output):
                explanation = ag.ai_explain(target, provider=provider)

        if json_output:
            print(json.dumps({"target": target, "explanation": explanation}, indent=2))
        else:
            render_ai_panel(explanation, title=f"AI Code Explanation: {target}")
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@ai_app.command(name="triage", help="Automated security risk triage and remediation plan.")
def ai_triage(
    session_id: str | None = typer.Option(
        None,
        "--session",
        "-s",
        help="Session ID. Defaults to active session.",
    ),
    provider: str | None = typer.Option(
        None,
        "--provider",
        "-p",
        help="AI provider override.",
    ),
    out_file: Path | None = typer.Option(
        None,
        "--out",
        "-o",
        help="Write triage report to Markdown file.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output triage report as JSON.",
    ),
) -> None:
    try:
        cfg = AndoGuardConfig.load()
        store = SessionStore(cfg)
        sid = session_id or (active.session_id if (active := store.get_active_session()) else None)

        if not sid:
            console.print("[yellow]No active session found. Specify --session <id>[/yellow]")
            raise typer.Exit(code=1)

        with AndoGuard.resume(sid) as ag:
            with status_spinner("Generating AI security triage...", enabled=not json_output):
                triage_report = ag.ai_triage(provider=provider)

        if out_file:
            out_file.write_text(triage_report, encoding="utf-8")
            console.print(f"[bold green]Saved AI triage report to[/bold green] '{out_file}'")
        elif json_output:
            print(json.dumps({"session_id": sid, "triage": triage_report}, indent=2))
        else:
            render_ai_panel(triage_report, title="Automated AI Security Triage Report")
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
