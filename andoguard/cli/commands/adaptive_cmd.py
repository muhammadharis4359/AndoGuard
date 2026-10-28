"""CLI subcommands for adaptive autonomous mode ('andoguard adaptive ...')."""


import typer

from andoguard.api import AndoGuard
from andoguard.cli.render import (
    console,
    render_adaptive_plan,
    render_adaptive_run,
    render_error,
    status_spinner,
)
from andoguard.config import AndoGuardConfig
from andoguard.errors import AndoGuardError
from andoguard.session.store import SessionStore

adaptive_app = typer.Typer(
    name="adaptive",
    help="Adaptive autonomous analysis agent, multi-step goal execution, and planning.",
    no_args_is_help=True,
)


@adaptive_app.command(name="run", help="Execute autonomous assessment loop toward goal.")
def run_autonomous(
    goal: str = typer.Argument(
        "Perform comprehensive security audit and identify vulnerabilities",
        help="High-level goal for the autonomous agent.",
    ),
    autonomy: str = typer.Option(
        "full",
        "--autonomy",
        "-a",
        help="Autonomy level: 'assist' (plan only), 'device' (on-device dynamic), or 'full'.",
    ),
    max_steps: int = typer.Option(
        10,
        "--max-steps",
        "-n",
        help="Maximum action steps to execute.",
    ),
    session_id: str | None = typer.Option(
        None,
        "--session",
        "-s",
        help="Target session ID. Defaults to active session.",
    ),
    provider: str | None = typer.Option(
        None,
        "--provider",
        "-p",
        help="AI provider override ('gemini', 'openai', 'anthropic', 'ollama', 'mock').",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output execution steps and results in JSON format.",
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
            with status_spinner(f"Running autonomous agent toward: '{goal}'...", enabled=not json_output):
                result = ag.adaptive_run(
                    goal=goal,
                    autonomy=autonomy,
                    max_steps=max_steps,
                    provider=provider,
                )

        render_adaptive_run(result, as_json=json_output)
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc


@adaptive_app.command(name="plan", help="Generate structured inspection step plan without executing tools.")
def plan_autonomous(
    goal: str = typer.Argument(
        "Perform comprehensive security audit and identify vulnerabilities",
        help="High-level goal to plan.",
    ),
    session_id: str | None = typer.Option(
        None,
        "--session",
        "-s",
        help="Target session ID. Defaults to active session.",
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
        help="Output step plan in JSON format.",
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
            with status_spinner("Generating autonomous step plan...", enabled=not json_output):
                plan_steps = ag.adaptive_plan(goal=goal, provider=provider)

        render_adaptive_plan(plan_steps, goal=goal, as_json=json_output)
    except AndoGuardError as exc:
        render_error(exc)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        render_error(exc)
        raise typer.Exit(code=1) from exc
