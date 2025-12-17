"""SploitGPT TUI Application."""

import asyncio
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.widgets import Footer, Header, Input, RichLog, Static

from sploitgpt.agent import Agent
from sploitgpt.core.boot import BootContext
from sploitgpt.core.config import get_settings
from sploitgpt.design_assets import get_banner_styled, get_phase_style


class TerminalSession:
    """Lightweight persistent shell session with cwd tracking."""

    def __init__(self, start_dir: str | Path | None = None) -> None:
        self.cwd = Path(start_dir or Path.cwd())

    async def run(self, command: str) -> str:
        """Run a command with simple built-ins (currently just `cd`)."""
        cmd = command.strip()
        if not cmd:
            return ""

        # Handle cd locally to preserve state across commands.
        if cmd.startswith("cd"):
            parts = cmd.split(maxsplit=1)
            target = parts[1] if len(parts) > 1 else str(Path.home())
            target_path = (self.cwd / target).expanduser().resolve()
            if not target_path.exists():
                return f"cd: no such file or directory: {target}"
            self.cwd = target_path
            return ""

        proc = await asyncio.create_subprocess_shell(
            cmd,
            cwd=str(self.cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode() if stdout else "(no output)"


class PromptInput(Input):
    """Custom input for the command prompt."""
    
    BINDINGS = [
        Binding("up", "history_prev", "Previous command", show=False),
        Binding("down", "history_next", "Next command", show=False),
    ]
    
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.history: list[str] = []
        self.history_index: int = -1
    
    def action_history_prev(self) -> None:
        """Go to previous command in history."""
        if self.history and self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.value = self.history[-(self.history_index + 1)]
    
    def action_history_next(self) -> None:
        """Go to next command in history."""
        if self.history_index > 0:
            self.history_index -= 1
            self.value = self.history[-(self.history_index + 1)]
        elif self.history_index == 0:
            self.history_index = -1
            self.value = ""


class StatusBar(Static):
    """Status bar showing current state."""
    
    def __init__(self, context: BootContext):
        super().__init__()
        self.context = context
    
    def compose(self) -> ComposeResult:
        msf = "[green]MSF[/]" if self.context.msf_connected else "[red]MSF[/]"
        llm = "[green]LLM[/]" if self.context.ollama_connected else "[red]LLM[/]"
        hosts = f"[cyan]{len(self.context.known_hosts)}[/] hosts"
        
        yield Static(f" {msf} | {llm} | {hosts} ")


class SploitGPTApp(App[Any]):
    """Main SploitGPT TUI Application."""
    
    TITLE = "SploitGPT"
    SUB_TITLE = "Autonomous AI Penetration Testing"
    
    CSS = """
    Screen {
        background: $surface;
    }
    
    #output {
        height: 1fr;
        border: solid $primary;
        padding: 0 1;
    }
    
    #input-container {
        height: 3;
        padding: 0 1;
    }
    
    #prompt-label {
        width: auto;
        color: $success;
        padding: 0 1 0 0;
    }
    
    #prompt-input {
        width: 1fr;
    }
    
    #status-bar {
        height: 1;
        dock: bottom;
        background: $surface-darken-1;
    }
    
    .choice-button {
        margin: 0 1;
    }
    """
    
    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit"),
        Binding("ctrl+l", "clear", "Clear"),
        Binding("ctrl+t", "toggle_shell_mode", "Shell mode"),
    ]
    
    def __init__(self, context: BootContext):
        super().__init__()
        self.context = context
        self.settings = get_settings()
        self.agent = Agent(context)
        self.awaiting_choice = False
        self.choice_callback = None
        self.shell = TerminalSession()
        self.shell_mode = False
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            RichLog(id="output", highlight=True, markup=True),
            Horizontal(
                Static("sploitgpt > ", id="prompt-label"),
                PromptInput(id="prompt-input", placeholder="Enter command or /help"),
                id="input-container"
            ),
        )
        yield Footer()
    
    async def on_mount(self) -> None:
        """Called when app is mounted."""
        output = self.query_one("#output", RichLog)
        
        # Welcome message with styled banner
        welcome_banner = get_banner_styled("main")
        output.write(welcome_banner)
        output.write("[bold cyan]TUI Build: conversational-by-default, !cmd for shell[/]")
        output.write("")
        
        model_name = self.settings.effective_model
        if self.context.ollama_connected and self.context.model_loaded:
            output.write(f"[green]✓[/] LLM connected; model loaded: [bold]{model_name}[/]")
        elif self.context.ollama_connected:
            output.write(
                f"[yellow]⚠[/] LLM reachable but model not loaded: [bold]{model_name}[/]"
            )
            output.write("Run `ollama pull <model>` or start the model.")
        else:
            output.write("[yellow]⚠[/] LLM not connected - run 'ollama serve' on host")
        
        if self.context.msf_connected:
            output.write("[green]✓[/] Metasploit RPC connected")
        else:
            output.write("[yellow]⚠[/] Metasploit RPC not available")
        
        if self.context.known_hosts:
            output.write(f"[cyan]ℹ[/] {len(self.context.known_hosts)} known hosts from prior recon")
        
        output.write("")
        output.write("[bold]How to use:[/] just type what you want (AI). Use !cmd for shell. /help for commands.")
        output.write(
            "[dim]Type /banner <phase> for a fresh banner (phases: main, recon, enumeration,"
        )
        output.write("[dim]vulnerability, exploitation, post_exploitation, privilege_escalation,")
        output.write("[dim]lateral_movement, persistence, exfiltration).[/]")
        
        # Focus input
        self.query_one("#prompt-input", PromptInput).focus()
    
    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle command submission."""
        if event.input.id != "prompt-input":
            return
        
        command = event.value.strip()
        if not command:
            return
        
        # Add to history
        prompt_input = self.query_one("#prompt-input", PromptInput)
        prompt_input.history.append(command)
        prompt_input.history_index = -1
        prompt_input.value = ""
        
        output = self.query_one("#output", RichLog)
        output.write(f"[bold green]>[/] {command}")

        # If we're waiting for an interactive choice, route input to the agent.
        if self.awaiting_choice:
            await self.handle_choice_input(command)
            return
        
        # Bang-prefix always forces shell execution.
        if command.startswith("!"):
            await self.handle_shell_command(command[1:].strip() or "")
            return

        # Shell mode routes everything to shell unless explicitly /command
        if self.shell_mode and not command.startswith("/"):
            await self.handle_shell_command(command)
            return

        # Slash-prefix is an explicit agent/system command.
        if command.startswith("/"):
            await self.handle_agent_command(command[1:].strip())
            return

        # Default: send to the agent (conversational).
        await self.handle_agent_command(command)
    
    async def handle_shell_command(self, command: str) -> None:
        """Execute a direct shell command."""
        output = self.query_one("#output", RichLog)

        try:
            result = await self.shell.run(command)
            if result:
                for line in result.split("\n"):
                    output.write(line)
        except Exception as e:
            output.write(f"[red]Error running shell command:[/] {e}")
    
    def _render_agent_response(self, response: Any) -> None:
        """Render an AgentResponse to the output log."""
        output = self.query_one("#output", RichLog)

        if response.type == "message":
            output.write(response.content)

        elif response.type == "command":
            output.write(f"[cyan]$[/] {response.content}")

        elif response.type == "result":
            for line in (response.content or "").split("\n"):
                output.write(f"  {line}")

        elif response.type == "info":
            output.write(response.content)

        elif response.type == "done":
            output.write(f"[bold green]✓[/] {response.content}")

        elif response.type == "choice":
            # Enter interactive mode
            self.awaiting_choice = True
            output.write("")
            output.write(f"[bold yellow]{response.question}[/]")
            for i, option in enumerate(response.options, 1):
                output.write(f"  [bold][{i}][/] {option}")
            output.write("[dim]Enter the option number.[/]")
            output.write("")

        elif response.type == "error":
            output.write(f"[red]Error:[/] {response.content}")

    async def handle_choice_input(self, user_input: str) -> None:
        """Handle user input when the agent is waiting on a choice/confirmation."""
        output = self.query_one("#output", RichLog)

        # Allow users to type choices with a leading '/' out of habit.
        if user_input.startswith("/"):
            user_input = user_input[1:]

        if not self.context.ollama_connected:
            output.write("[red]Error:[/] LLM not connected. Start Ollama first.")
            self.awaiting_choice = False
            return

        # Assume we'll exit choice mode unless the agent asks another question
        self.awaiting_choice = False

        try:
            async for response in self.agent.submit_choice(user_input):
                self._render_agent_response(response)
                if response.type == "choice":
                    # Agent needs more input
                    return
        except Exception as e:
            import traceback

            output.write(f"[red]Agent error:[/] {e}")
            output.write(f"[dim]{traceback.format_exc()}[/]")

    async def handle_agent_command(self, command: str) -> None:
        """Handle an AI-assisted command."""
        output = self.query_one("#output", RichLog)
        
        if command.lower() == "help":
            output.write("")
            output.write("[bold cyan]SploitGPT Commands[/]")
            output.write("")
            output.write("  [bold]/scan[/] <target>     - Scan a target")
            output.write("  [bold]/enumerate[/] <target> - Enumerate services")
            output.write("  [bold]/exploit[/] <target>   - Find and run exploits")
            output.write("  [bold]/privesc[/]            - Privilege escalation")
            output.write("  [bold]/banner[/] <phase>     - Display ASCII banner for attack phase")
            output.write("  [bold]/auto[/] on|off        - Toggle autonomous execution confirmations")
            output.write("  [bold]/shell[/] on|off       - Route input to a local shell (Ctrl+T toggles)")
            output.write("  [bold]!<cmd>[/]              - Run a single shell command (e.g., !ls -la)")
            output.write("")
            output.write("[bold]Default behavior:[/] plain input goes to the AI; use !cmd for shell.")
            output.write("  [bold]/help[/]               - Show this help")
            output.write("")
            output.write("[bold]Available banner phases:[/]")
            output.write("  recon, enumeration, vulnerability, exploitation,")
            output.write("  post_exploitation, privilege_escalation, lateral_movement,")
            output.write("  persistence, exfiltration")
            output.write("")
            output.write("[dim]Or just describe what you want in natural language:[/]")
            output.write("[dim]  /find sql injection vulnerabilities on 10.0.0.1[/]")
            output.write("")
            return
        
        # Handle autonomous mode toggle
        if command.lower().startswith("auto"):
            parts = command.split(maxsplit=1)
            if not self.agent:
                output.write("[red]Error:[/] Agent not initialized")
                return

            if len(parts) == 1:
                state = "ON" if self.agent.autonomous else "OFF"
                output.write(f"Autonomous mode is [bold]{state}[/]. Use /auto on or /auto off.")
                return

            value = parts[1].strip().lower()
            if value in ("on", "true", "1"):
                self.agent.autonomous = True
            elif value in ("off", "false", "0"):
                self.agent.autonomous = False
            elif value in ("toggle",):
                self.agent.autonomous = not self.agent.autonomous
            else:
                output.write("[red]Error:[/] Usage: /auto on|off")
                return

            state = "ON" if self.agent.autonomous else "OFF"
            output.write(f"Autonomous mode is now [bold]{state}[/].")
            return

        # Handle shell mode toggle
        if command.lower().startswith("shell"):
            parts = command.split(maxsplit=1)
            if len(parts) == 1:
                state = "ON" if self.shell_mode else "OFF"
                output.write(f"Shell passthrough is [bold]{state}[/]. Use /shell on or /shell off.")
                return

            value = parts[1].strip().lower()
            if value in ("on", "true", "1"):
                self.shell_mode = True
            elif value in ("off", "false", "0"):
                self.shell_mode = False
            elif value in ("toggle",):
                self.shell_mode = not self.shell_mode
            else:
                output.write("[red]Error:[/] Usage: /shell on|off")
                return

            state = "ON" if self.shell_mode else "OFF"
            self._update_prompt_label()
            output.write(f"Shell passthrough is now [bold]{state}[/].")
            return

        # Handle banner command
        if command.lower().startswith("banner"):
            parts = command.split(maxsplit=1)
            phase = parts[1].lower() if len(parts) > 1 else "main"
            
            # Display the banner
            try:
                banner_text = get_banner_styled(phase)
                output.write("")
                output.write(banner_text)
                output.write("")
                
                # Show phase information if it's a specific phase
                if phase != "main":
                    style = get_phase_style(phase)
                    output.write(f"[{style['color']}]{style['icon']} Phase: {style['short']}[/]")
                    output.write("")
                    
            except Exception as e:
                output.write(f"[red]Error displaying banner:[/] {e}")
                output.write("[dim]Available phases: main, recon, enumeration, vulnerability, exploitation, post_exploitation, privilege_escalation, lateral_movement, persistence, exfiltration[/]")
            
            return
        
        if not self.context.ollama_connected:
            output.write("[red]Error:[/] LLM not connected. Start Ollama first.")
            return
        
        output.write("[dim]Thinking...[/]")
        
        # Process with agent
        try:
            async for response in self.agent.process(command):
                self._render_agent_response(response)
                if response.type == "choice":
                    # Agent is pausing for user input
                    return
        except Exception as e:
            import traceback
            output.write(f"[red]Agent error:[/] {e}")
            output.write(f"[dim]{traceback.format_exc()}[/]")
    
    def action_clear(self) -> None:
        """Clear the output."""
        self.query_one("#output", RichLog).clear()

    def action_toggle_shell_mode(self) -> None:
        """Toggle shell passthrough mode via keybinding."""
        self.shell_mode = not self.shell_mode
        self._update_prompt_label()
        state = "ON" if self.shell_mode else "OFF"
        output = self.query_one("#output", RichLog)
        output.write(f"[dim]Shell passthrough is now {state} (Ctrl+T).[/]")
    
    async def action_quit(self) -> None:
        """Quit the application."""
        try:
            await self.agent.aclose()
        except Exception:
            pass
        self.exit()

    def _update_prompt_label(self) -> None:
        """Refresh the prompt label to reflect current mode."""
        label = self.query_one("#prompt-label", Static)
        label.update("shell > " if self.shell_mode else "sploitgpt > ")
