"""
SploitGPT CLI Entry Point
"""

import argparse
import asyncio
import sys
from collections.abc import AsyncGenerator
from typing import Any

from rich.console import Console

from sploitgpt.core.boot import boot_sequence
from sploitgpt.design_assets import get_banner_styled

console = Console()


async def _run_agent_stream(
    agent: Any,
    stream: AsyncGenerator[Any, None],
    *,
    auto_choice: bool = False,
    require_finish: bool = False,
) -> int:
    """Render an agent response stream, handling interactive choices."""
    saw_done = False
    async for response in stream:
        if response.type == "message":
            console.print(response.content)

        elif response.type == "command":
            console.print(f"[cyan]$[/cyan] {response.content}")

        elif response.type == "result":
            console.print(response.content)

        elif response.type == "error":
            console.print(f"[red]Error:[/red] {response.content}")
            return 1

        elif response.type == "done":
            saw_done = True
            console.print(f"\n[green]✓[/green] {response.content}")
            return 0

        elif response.type == "choice":
            console.print(f"\n[yellow]{response.question}[/yellow]")
            for i, opt in enumerate(response.options, 1):
                console.print(f"  [{i}] {opt}")

            if auto_choice:
                # Prefer enabling autonomous confirmations when offered.
                chosen_idx = 1
                for i, opt in enumerate(response.options, 1):
                    if "autonomous" in str(opt).lower():
                        chosen_idx = i
                        break
                selection = str(chosen_idx)
            else:
                selection = console.input("[bold yellow]Choice>[/bold yellow] ").strip()

            # Resume via submit_choice; this may itself yield nested choices.
            return await _run_agent_stream(
                agent,
                agent.submit_choice(selection),
                auto_choice=auto_choice,
                require_finish=require_finish,
            )

    if require_finish and not saw_done:
        return 2
    return 0


def print_banner() -> None:
    """Print the SploitGPT banner."""
    banner = get_banner_styled("main")
    console.print(banner)


async def run_headless(context: Any, task: str, *, autonomous: bool, auto_choice: bool) -> int:
    """Run a single task without TUI."""
    from sploitgpt.agent import Agent

    if not context.ollama_connected:
        console.print("[red]Error: LLM not available. Start Ollama first.[/red]")
        return 1

    agent = Agent(context)
    agent.autonomous = autonomous

    console.print(f"\n[cyan]Task:[/cyan] {task}\n")

    prompt = task
    for _attempt in range(1, 4):
        rc = await _run_agent_stream(
            agent,
            agent.process(prompt),
            auto_choice=auto_choice,
            require_finish=auto_choice,
        )
        if rc != 2:
            return rc

        # If we're in non-interactive mode and the model didn't call finish, nudge it.
        prompt = (
            "Call the finish tool now for the previous task. Do not ask follow-up questions. "
            "Provide a concise one-line summary."
        )

    console.print("[red]Error:[/red] Task did not terminate with finish.")
    return 1


async def async_main(args: argparse.Namespace) -> int:
    """Async main entry point."""

    # For TUI mode, we need minimal output before Textual takes over
    is_tui_mode = not args.task and not args.cli and not getattr(args, "resume", None)

    if not is_tui_mode:
        print_banner()
        console.print("\n[bold cyan]Initializing SploitGPT...[/]\n")

    # Run boot sequence (with quiet mode for TUI)
    try:
        context = await boot_sequence(quiet=is_tui_mode)
    except Exception as e:
        console.print(f"[bold red]Boot failed:[/] {e}")
        return 1

    # Resume mode
    if getattr(args, "resume", None):
        return await run_resume_mode(
            context,
            args.resume,
            autonomous=bool(getattr(args, "autonomous", False)),
        )

    # Headless mode with task
    if args.task:
        return await run_headless(
            context,
            args.task,
            autonomous=bool(getattr(args, "autonomous", False) or getattr(args, "yes", False)),
            auto_choice=bool(getattr(args, "yes", False)),
        )

    # CLI mode
    if args.cli:
        return await run_cli_loop(
            context,
            autonomous=bool(getattr(args, "autonomous", False)),
        )

    # Default: TUI mode - clear screen first to avoid artifacts
    import os

    os.system("clear" if os.name != "nt" else "cls")

    from sploitgpt.tui.app import SploitGPTApp

    app = SploitGPTApp(context=context)
    await app.run_async()

    return 0


def _show_session_list(console: Console) -> str | None:
    """Display session list and prompt for selection. Returns session ID or None."""
    from sploitgpt.core.config import get_settings
    from sploitgpt.training.collector import SessionCollector

    settings = get_settings()
    collector = SessionCollector(settings.sessions_dir / "sessions.db")
    sessions = collector.list_sessions(limit=10)

    if not sessions:
        console.print("[yellow]No previous sessions found.[/yellow]")
        return None

    console.print("\n[bold cyan]Recent Sessions[/bold cyan]\n")

    for i, session in enumerate(sessions, 1):
        # Format date nicely
        try:
            from datetime import datetime

            started = datetime.fromisoformat(session.started_at)
            date_str = started.strftime("%Y-%m-%d %H:%M")
        except Exception:
            date_str = session.started_at[:16] if session.started_at else "Unknown"

        # Status indicator
        if session.ended_at:
            status = "[green]✓[/green]" if session.successful else "[yellow]○[/yellow]"
        else:
            status = "[cyan]◐[/cyan]"  # In progress

        # Task description (truncate if long)
        task = (
            session.task_description[:50] + "..."
            if len(session.task_description) > 50
            else session.task_description
        )
        if not task:
            task = "(no task description)"

        console.print(
            f"  [{i}] {status} {session.id} | {date_str} | {session.turn_count} turns | {task}"
        )

    console.print()

    try:
        selection = console.input(
            "[bold yellow]Select session (number or ID)>[/bold yellow] "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        return None

    if not selection:
        return None

    # Handle numeric selection
    if selection.isdigit():
        idx = int(selection) - 1
        if 0 <= idx < len(sessions):
            return sessions[idx].id
        console.print("[red]Invalid selection.[/red]")
        return None

    # Handle direct ID
    return selection


async def run_resume_mode(context: Any, resume_arg: str, *, autonomous: bool) -> int:
    """Resume a previous session."""
    from sploitgpt.agent import Agent

    # If "list" or no specific ID, show session picker
    if resume_arg == "list":
        session_id = _show_session_list(console)
        if not session_id:
            return 0
    else:
        session_id = resume_arg

    # Try to restore the agent
    console.print(f"\n[cyan]Resuming session:[/cyan] {session_id}\n")

    agent = Agent.from_session(session_id, context)
    if not agent:
        console.print(f"[red]Error:[/red] Session '{session_id}' not found.")
        return 1

    agent.autonomous = autonomous

    # Show context
    console.print(f"[dim]Target: {agent.target or 'Not set'}[/dim]")
    console.print(f"[dim]Phase: {agent.current_phase}[/dim]")
    console.print(f"[dim]Services discovered: {len(agent.discovered_services)}[/dim]")
    console.print(f"[dim]Conversation turns: {len(agent.conversation)}[/dim]")
    console.print()

    # Continue with CLI loop using the restored agent
    return await _run_cli_loop_with_agent(context, agent)


async def _run_cli_loop_with_agent(context: Any, agent: Any) -> int:
    """Run CLI loop with an existing agent instance."""

    def _sanitize_prompt_input(value: str) -> str:
        i = 0
        while i < len(value):
            ch = value[i]
            if ch.isspace() or ord(ch) < 32:
                i += 1
                continue
            break
        return value[i:]

    console.print("[dim]Type commands or '/help' for assistance. Ctrl+C to exit.[/dim]\n")

    while True:
        try:
            user_input = console.input("[bold green]sploitgpt>[/bold green] ")
        except EOFError:
            break

        user_input = _sanitize_prompt_input(user_input)

        if not user_input:
            continue

        if user_input.strip().lower() in ("exit", "quit", "q"):
            # Save state before exiting
            agent.save_state()
            break

        # If we're waiting on a choice/confirmation, treat any input as the answer.
        if getattr(agent, "_pending", None) is not None:
            await _run_agent_stream(agent, agent.process(user_input))
            console.print()
            continue

        # Direct shell command
        if not user_input.startswith("/"):
            from sploitgpt.tools import execute_tool

            result = await execute_tool("terminal", {"command": user_input, "timeout": 0})
            if result:
                console.print(result)
            continue

        # AI command
        task = user_input[1:].strip()

        if task.lower() == "help":
            console.print("""
[bold cyan]SploitGPT Commands[/bold cyan]

  [bold]/scan[/bold] <target>       Scan a target
  [bold]/enumerate[/bold] <svc>    Enumerate a service
  [bold]/exploit[/bold] <target>   Find and exploit vulnerabilities
  [bold]/privesc[/bold]            Privilege escalation techniques
  [bold]/resume[/bold]             Resume a previous session
  [bold]/save[/bold]               Save current session state
  [bold]/auto[/bold] on|off        Toggle autonomous mode
  
Or describe any task in natural language.
""")
            continue

        # Handle /save command
        if task.lower() == "save":
            agent.save_state()
            console.print(f"[green]Session {agent.session_id} state saved.[/green]")
            continue

        # Handle /resume command
        if task.lower().startswith("resume"):
            parts = task.split(maxsplit=1)
            new_session_id: str | None
            if len(parts) > 1:
                new_session_id = parts[1].strip()
            else:
                new_session_id = _show_session_list(console)

            if new_session_id:
                from sploitgpt.agent import Agent

                new_agent = Agent.from_session(new_session_id, context)
                if new_agent:
                    agent.save_state()  # Save current session first
                    agent = new_agent
                    console.print(f"[green]Resumed session {new_session_id}[/green]")
                    console.print(
                        f"[dim]Target: {agent.target or 'Not set'} | Phase: {agent.current_phase}[/dim]"
                    )
                else:
                    console.print(f"[red]Session '{new_session_id}' not found.[/red]")
            continue

        # Handle autonomous mode toggle
        if task.lower().startswith("auto"):
            parts = task.split(maxsplit=1)
            if len(parts) == 1:
                state = "ON" if agent.autonomous else "OFF"
                console.print(f"Autonomous mode is [bold]{state}[/]. Use /auto on or /auto off.")
                continue

            value = parts[1].strip().lower()
            if value in ("on", "true", "1"):
                agent.autonomous = True
            elif value in ("off", "false", "0"):
                agent.autonomous = False
            elif value in ("toggle",):
                agent.autonomous = not agent.autonomous
            else:
                console.print("[red]Error:[/red] Usage: /auto on|off")
                continue

            state = "ON" if agent.autonomous else "OFF"
            console.print(f"Autonomous mode is now [bold]{state}[/].")
            continue

        if not context.ollama_connected:
            console.print("[yellow]LLM not available. Start Ollama first.[/yellow]")
            continue

        await _run_agent_stream(agent, agent.process(task))

        # Periodically save state after agent interactions
        agent.save_state()

        console.print()

    console.print("[dim]Goodbye.[/dim]")
    return 0


async def run_cli_loop(context: Any, *, autonomous: bool) -> int:
    """Run interactive CLI loop (no TUI)."""
    from sploitgpt.agent import Agent

    agent = Agent(context)
    agent.autonomous = autonomous

    return await _run_cli_loop_with_agent(context, agent)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="SploitGPT - Autonomous AI Penetration Testing")
    parser.add_argument("--cli", "-c", action="store_true", help="Run in CLI mode (no TUI)")
    parser.add_argument("--task", "-t", type=str, help="Run a single task and exit")
    parser.add_argument("--version", "-v", action="version", version="SploitGPT 0.1.0")
    parser.add_argument(
        "--autonomous",
        "-a",
        action="store_true",
        help="Auto-approve execution tools (skip confirmation prompts)",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Non-interactive mode for --task: auto-approve tools and auto-select the first option",
    )
    parser.add_argument(
        "--resume",
        "-r",
        type=str,
        nargs="?",
        const="list",
        help="Resume a previous session. Use session ID or omit to see a list of sessions.",
    )

    args = parser.parse_args()

    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        console.print("\n[dim]Goodbye.[/]")
        return 0


if __name__ == "__main__":
    sys.exit(main())
