"""
MSF Visual Terminal Viewer (PTY-based)

Opens msfconsole in a separate terminal window and echoes commands
that the LLM executes via RPC, so users can watch/verify in real-time.

Workflow:
1. User confirms action in SploitGPT TUI
2. LLM executes via MSF RPC
3. Viewer shows equivalent msfconsole command + output

This is an optional add-on feature. To disable:
  - Set SPLOITGPT_MSF_VIEWER_ENABLED=false in .env
  - Or set msf_viewer_enabled=False in config

To remove entirely:
  - Delete this file
  - Remove msf_viewer_enabled from config.py
  - Remove the open_msf_viewer() call from boot.py
"""

import logging
import os
import pty
import select
import shutil
import subprocess
import threading
import time
from typing import Literal

logger = logging.getLogger(__name__)


# =============================================================================
# ANSI Color Codes for Visual Distinction
# =============================================================================
class Colors:
    """ANSI escape codes for terminal colors."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Operation type colors
    RED = "\033[91m"  # Exploits - high impact
    YELLOW = "\033[93m"  # Auxiliary/Scanners - info gathering
    GREEN = "\033[92m"  # Sessions - success/active
    CYAN = "\033[96m"  # Module info/options - informational
    MAGENTA = "\033[95m"  # Jobs - background tasks
    BLUE = "\033[94m"  # General commands
    WHITE = "\033[97m"  # Output/results
    GRAY = "\033[90m"  # Separators/banners


# Operation type to color mapping
OP_COLORS = {
    "exploit": Colors.RED,
    "auxiliary": Colors.YELLOW,
    "scanner": Colors.YELLOW,
    "session": Colors.GREEN,
    "job": Colors.MAGENTA,
    "module_info": Colors.CYAN,
    "search": Colors.BLUE,
    "general": Colors.WHITE,
    "output": Colors.DIM + Colors.WHITE,
    "separator": Colors.GRAY,
}


# Module-level state
_viewer_process: subprocess.Popen | None = None
_viewer_opened_once: bool = False
_pty_master_fd: int | None = None
_viewer_ready: bool = False
_viewer_lock = threading.Lock()
_last_operation_type: str | None = None  # Track for visual separators


def _has_display() -> bool:
    """Check if a display server is available (X11 or Wayland)."""
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _get_desktop_terminal() -> str | None:
    """Get the preferred terminal for the current desktop environment."""
    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").lower()

    # Map desktop environments to their native terminals
    if "gnome" in desktop or "unity" in desktop:
        if shutil.which("gnome-terminal"):
            return "gnome-terminal"
    elif "kde" in desktop or "plasma" in desktop:
        if shutil.which("konsole"):
            return "konsole"
    elif "xfce" in desktop:
        if shutil.which("xfce4-terminal"):
            return "xfce4-terminal"
    elif "mate" in desktop:
        if shutil.which("mate-terminal"):
            return "mate-terminal"

    return None  # Fall back to generic detection


def _find_terminal() -> str | None:
    """Find an available terminal emulator on the system."""
    # First, try the desktop-native terminal
    desktop_term = _get_desktop_terminal()
    if desktop_term:
        return desktop_term

    # Fallback: scan common terminals in preference order
    terminals = [
        "gnome-terminal",
        "konsole",
        "xfce4-terminal",
        "mate-terminal",
        "tilix",
        "terminator",
        "alacritty",
        "kitty",
        "xterm",  # Fallback, available on most X11 systems
    ]

    for term in terminals:
        if shutil.which(term):
            return term

    return None


def _get_intro_banner() -> str:
    """Generate the intro banner shown when viewer opens."""
    return f"""{Colors.GRAY}
{"=" * 70}
{Colors.BOLD}{Colors.CYAN}  SploitGPT MSF Viewer - Real-Time Learning Mode{Colors.RESET}{Colors.GRAY}
{"=" * 70}

  You are watching SploitGPT's Metasploit operations in real-time.
  
  What you'll see:
  {Colors.RED}RED{Colors.GRAY}     = Exploit execution (offensive actions)
  {Colors.YELLOW}YELLOW{Colors.GRAY}  = Auxiliary/Scanner modules (recon & info gathering)
  {Colors.GREEN}GREEN{Colors.GRAY}   = Session operations (active shells/connections)
  {Colors.MAGENTA}MAGENTA{Colors.GRAY} = Background jobs
  {Colors.CYAN}CYAN{Colors.GRAY}    = Module info & options
  {Colors.BLUE}BLUE{Colors.GRAY}    = General commands

  Commands shown here mirror what the AI executes via RPC.
  This is a READ-ONLY view - type in your main terminal to interact.
  
{"=" * 70}{Colors.RESET}
"""


def _build_terminal_command(terminal: str, slave_name: str) -> list[str]:
    """Build the command to open a terminal connected to our PTY slave.

    The terminal runs msfconsole with stdin connected to our PTY slave,
    allowing us to inject commands from the parent process. The user sees
    both the injected commands and msfconsole's output in the terminal window.
    """
    title = "SploitGPT MSF Viewer"

    # Connect terminal stdin to PTY slave so we can inject commands.
    # stdout/stderr stay connected to the terminal for display.
    # The `cat` at the end keeps the terminal open even if msfconsole exits.
    connect_cmd = f"msfconsole -q < {slave_name}; echo '[MSF Viewer] msfconsole exited'; cat"

    # Each terminal has slightly different CLI syntax
    if terminal == "gnome-terminal":
        return ["gnome-terminal", f"--title={title}", "--", "bash", "-c", connect_cmd]

    elif terminal == "konsole":
        return ["konsole", f"--title={title}", "-e", "bash", "-c", connect_cmd]

    elif terminal == "xfce4-terminal":
        # xfce4-terminal -e takes a single command string, not shell
        return ["xfce4-terminal", f"--title={title}", "-x", "bash", "-c", connect_cmd]

    elif terminal == "mate-terminal":
        # mate-terminal -e also takes a single command
        return ["mate-terminal", f"--title={title}", "-x", "bash", "-c", connect_cmd]

    elif terminal == "tilix":
        return ["tilix", f"--title={title}", "-e", "bash", "-c", connect_cmd]

    elif terminal == "terminator":
        # terminator -e takes a single command string
        return ["terminator", f"--title={title}", "-x", "bash", "-c", connect_cmd]

    elif terminal == "alacritty":
        return ["alacritty", "--title", title, "-e", "bash", "-c", connect_cmd]

    elif terminal == "kitty":
        return ["kitty", "--title", title, "bash", "-c", connect_cmd]

    else:  # xterm and others
        return ["xterm", "-title", title, "-e", "bash", "-c", connect_cmd]


def is_viewer_open() -> bool:
    """Check if the MSF viewer terminal is currently open."""
    global _viewer_process

    if _viewer_process is None:
        return False

    # Check if process is still running
    return _viewer_process.poll() is None


def is_viewer_ready() -> bool:
    """Check if the viewer is ready to receive commands."""
    return _viewer_ready and is_viewer_open()


def open_msf_viewer(*, force: bool = False) -> bool:
    """
    Open msfconsole in a new terminal window with PTY control.

    Args:
        force: If True, open even if already opened once this session.
               By default, only opens on the first MSF RPC connection.

    Returns:
        True if viewer was opened (or already open), False on failure.
    """
    global _viewer_process, _viewer_opened_once, _pty_master_fd, _viewer_ready

    with _viewer_lock:
        # Already open - nothing to do
        if is_viewer_open():
            logger.debug("MSF viewer already open")
            return True

        # Only auto-open once per session (unless forced)
        if _viewer_opened_once and not force:
            logger.debug("MSF viewer was closed by user, not reopening")
            return False

        # Check for display server (skip in headless/container environments)
        if not _has_display():
            logger.debug("No display available (headless mode), skipping MSF viewer")
            return False

        # Find a terminal emulator
        terminal = _find_terminal()
        if not terminal:
            logger.warning(
                "No terminal emulator found for MSF viewer. "
                "Install gnome-terminal, konsole, xfce4-terminal, or xterm."
            )
            return False

        # Check if msfconsole is available
        if not shutil.which("msfconsole"):
            logger.warning("msfconsole not found in PATH, cannot open MSF viewer")
            return False

        # Create PTY pair
        try:
            master_fd, slave_fd = pty.openpty()
            slave_name = os.ttyname(slave_fd)

            # Keep slave_fd open until terminal process starts - it needs to
            # be able to open the slave device by name
            _pty_master_fd = master_fd

            # Store slave_fd to close after terminal starts
            _slave_fd_temp = slave_fd

        except Exception as e:
            logger.error(f"Failed to create PTY: {e}")
            return False

        # Build and run the command
        cmd = _build_terminal_command(terminal, slave_name)

        try:
            logger.info(f"Opening MSF viewer with {terminal}")
            _viewer_process = subprocess.Popen(
                cmd,
                start_new_session=True,  # Detach from parent process
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _viewer_opened_once = True

            # Close slave_fd in parent after terminal has started
            # Terminal will open the slave device by name
            try:
                os.close(_slave_fd_temp)
            except Exception:
                pass

            # Start a thread to wait for msfconsole prompt
            def _wait_for_ready():
                global _viewer_ready, _pty_master_fd

                # Wait for msfconsole to be ready by watching for the prompt
                # The msf prompt looks like "msf6 >" or "msf >"
                start_time = time.time()
                max_wait = 30  # Maximum 30 seconds
                buffer = b""

                while time.time() - start_time < max_wait:
                    if _pty_master_fd is None:
                        logger.debug("PTY closed while waiting for prompt")
                        return

                    try:
                        # Use select to check if data is available (non-blocking)
                        ready, _, _ = select.select([_pty_master_fd], [], [], 0.5)
                        if ready:
                            data = os.read(_pty_master_fd, 4096)
                            if data:
                                buffer += data
                                # Check for msf prompt pattern
                                if b"msf" in buffer and b">" in buffer:
                                    logger.debug("Detected msfconsole prompt")
                                    _viewer_ready = True
                                    # Send the intro banner
                                    _send_intro_banner()
                                    return
                    except (OSError, IOError) as e:
                        logger.debug(f"Error reading PTY during prompt wait: {e}")
                        break

                # Fallback: mark ready after timeout even without prompt detection
                logger.debug("MSF viewer ready (timeout fallback)")
                _viewer_ready = True
                _send_intro_banner()

            threading.Thread(target=_wait_for_ready, daemon=True).start()

            return True

        except FileNotFoundError:
            logger.error(f"Terminal {terminal} not found")
            if _pty_master_fd:
                os.close(_pty_master_fd)
                _pty_master_fd = None
            return False

        except PermissionError:
            logger.error(f"Permission denied running {terminal}")
            if _pty_master_fd:
                os.close(_pty_master_fd)
                _pty_master_fd = None
            return False

        except Exception as e:
            logger.error(f"Failed to open MSF viewer: {e}")
            if _pty_master_fd:
                os.close(_pty_master_fd)
                _pty_master_fd = None
            return False


def send_to_viewer(command: str) -> bool:
    """
    Send a command to the MSF viewer terminal.

    The command will be typed into msfconsole and executed,
    allowing the user to see both the command and its output.

    Args:
        command: The msfconsole command to execute (without trailing newline)

    Returns:
        True if sent successfully, False if viewer not available.
    """
    global _pty_master_fd

    if not is_viewer_ready():
        logger.debug(f"Viewer not ready, skipping command: {command[:50]}...")
        return False

    if _pty_master_fd is None:
        return False

    try:
        # Write command + newline to PTY
        cmd_bytes = (command + "\n").encode("utf-8")
        os.write(_pty_master_fd, cmd_bytes)
        logger.debug(f"Sent to viewer: {command}")
        return True

    except OSError as e:
        logger.debug(f"Failed to write to viewer PTY: {e}")
        return False
    except Exception as e:
        logger.debug(f"Error sending to viewer: {e}")
        return False


def _send_intro_banner() -> None:
    """Send the intro banner to the viewer after it's ready."""
    if not is_viewer_ready():
        return

    banner = _get_intro_banner()
    # Send banner as an echo command so it displays nicely
    for line in banner.split("\n"):
        send_to_viewer(f"echo '{line}'")
        time.sleep(0.01)  # Small delay to prevent buffer overflow


def send_separator(operation_type: str | None = None) -> None:
    """
    Send a visual separator to the viewer between different operations.

    Args:
        operation_type: The type of operation about to be performed.
                       Used to decide if separator is needed.
    """
    global _last_operation_type

    if not is_viewer_ready():
        return

    # Only send separator if operation type changed
    if operation_type and operation_type != _last_operation_type:
        color = OP_COLORS.get("separator", Colors.GRAY)
        separator = f"echo '{color}{'─' * 50}{Colors.RESET}'"
        send_to_viewer(separator)
        _last_operation_type = operation_type


def send_colored_command(command: str, operation_type: str = "general") -> bool:
    """
    Send a command to the viewer with color coding based on operation type.

    Args:
        command: The msfconsole command to execute
        operation_type: Type of operation for color selection

    Returns:
        True if sent successfully, False otherwise.
    """
    if not is_viewer_ready():
        return False

    color = OP_COLORS.get(operation_type, Colors.WHITE)
    # Wrap command in color codes via echo, then execute
    # Actually, we can't colorize msfconsole input - just send the command
    # The color coding will be applied to our echo_output messages instead
    return send_to_viewer(command)


def close_msf_viewer() -> bool:
    """
    Close the MSF viewer terminal if open.

    Returns:
        True if closed, False if wasn't open.
    """
    global _viewer_process, _pty_master_fd, _viewer_ready

    with _viewer_lock:
        if not is_viewer_open():
            return False

        _viewer_ready = False

        # Close PTY master
        if _pty_master_fd is not None:
            try:
                os.close(_pty_master_fd)
            except Exception:
                pass
            _pty_master_fd = None

        try:
            _viewer_process.terminate()
            _viewer_process.wait(timeout=5)
            _viewer_process = None
            return True
        except Exception as e:
            logger.warning(f"Error closing MSF viewer: {e}")
            # Force kill if terminate didn't work
            try:
                _viewer_process.kill()
                _viewer_process = None
            except Exception:
                pass
            return True


# =============================================================================
# RPC-to-Console Command Mapping (Auto-echo)
# =============================================================================

# Track current module context for multi-step commands
_current_module: str | None = None


def ensure_viewer_open() -> bool:
    """
    Ensure the MSF viewer is open if enabled in settings.

    Called automatically when MSF RPC calls are made.
    Returns True if viewer is open/ready, False otherwise.
    """
    if is_viewer_open():
        return True

    try:
        from sploitgpt.core.config import get_settings

        settings = get_settings()
        if not getattr(settings, "msf_viewer_enabled", False):
            return False
    except Exception:
        return False

    return open_msf_viewer()


def _get_operation_type(method: str, params: list) -> str:
    """Determine the operation type for color coding and separators."""
    if method.startswith("session."):
        return "session"
    if method.startswith("job."):
        return "job"
    if method == "module.search":
        return "search"
    if method in ("module.info", "module.options"):
        return "module_info"
    if method == "module.execute" and len(params) >= 1:
        mod_type = params[0]
        if mod_type == "exploit":
            return "exploit"
        if mod_type in ("auxiliary", "scanner"):
            return "auxiliary"
    return "general"


def echo_rpc_call(method: str, params: list) -> None:
    """
    Auto-echo any MSF RPC call as the equivalent msfconsole command.

    This is called from MetasploitRPC._call() so ALL RPC operations
    are automatically shown in the viewer.

    Args:
        method: RPC method name (e.g., "module.search", "session.list")
        params: RPC parameters (token already stripped)
    """
    global _current_module

    # Skip internal/auth methods before trying to open viewer
    if method in ("auth.login", "auth.logout", "console.create", "console.read", "console.destroy"):
        return

    # Try to ensure viewer is open for meaningful commands
    ensure_viewer_open()

    cmd = _rpc_to_console(method, params)
    if cmd:
        # Determine operation type for visual formatting
        op_type = _get_operation_type(method, params)

        # Add visual separator between different operation types
        send_separator(op_type)

        # Send header comment with operation type (colored)
        color = OP_COLORS.get(op_type, Colors.WHITE)
        header = f"echo '{color}[{op_type.upper()}]{Colors.RESET}'"
        send_to_viewer(header)

        # Handle multi-command sequences (e.g., module.execute)
        if isinstance(cmd, list):
            for c in cmd:
                send_to_viewer(c)
                time.sleep(0.05)  # Small delay for readability
        else:
            send_to_viewer(cmd)

        # Track module context
        if method == "module.execute" and len(params) >= 2:
            _current_module = params[1]  # module name


def _rpc_to_console(method: str, params: list) -> str | list[str] | None:
    """
    Map an RPC method + params to equivalent msfconsole command(s).

    Returns None for methods that don't have a console equivalent
    or that we don't want to echo (like auth).
    """
    global _current_module

    # Module operations
    if method == "module.search":
        return f"search {params[0]}" if params else None

    if method == "module.info":
        # params: [type, name]
        if len(params) >= 2:
            _current_module = params[1]
            return [f"use {params[1]}", "info"]
        return None

    if method == "module.options":
        # params: [type, name]
        if len(params) >= 2:
            _current_module = params[1]
            return [f"use {params[1]}", "show options"]
        return None

    if method == "module.execute":
        # params: [type, name, options_dict]
        if len(params) >= 3:
            module_name = params[1]
            options = params[2] if isinstance(params[2], dict) else {}
            cmds = [f"use {module_name}"]
            for k, v in options.items():
                cmds.append(f"set {k} {v}")
            cmds.append("exploit" if params[0] == "exploit" else "run")
            return cmds
        return None

    # Session operations
    if method == "session.list":
        return "sessions"

    if method == "session.shell_write":
        # params: [session_id, data]
        if len(params) >= 2:
            # Show the command being sent to the session
            data = params[1].strip()
            if data:
                return f"# Session {params[0]}: {data}"
        return None

    if method == "session.stop":
        # params: [session_id]
        if params:
            return f"sessions -k {params[0]}"
        return None

    # Job operations
    if method == "job.list":
        return "jobs"

    if method == "job.stop":
        # params: [job_id]
        if params:
            return f"jobs -k {params[0]}"
        return None

    # Console operations (these are already console commands)
    if method == "console.write":
        # params: [console_id, command]
        if len(params) >= 2:
            return params[1].strip()
        return None

    # Skip auth, console management, and other internal methods
    # auth.login, auth.logout, console.create, console.destroy
    # Note: console.read is intentionally skipped - output appears in the viewer terminal
    return None


def echo_output(output: str, result_type: str = "general", max_lines: int = 15) -> None:
    """
    Echo output/results to the viewer with formatting.

    This can be called after receiving MSF RPC results to show
    what was returned, helping users correlate commands with results.

    Args:
        output: The output text to display
        result_type: Type of result for color coding (session, exploit, auxiliary, etc.)
        max_lines: Maximum number of lines to display (default 15)
    """
    if not output or not output.strip():
        return

    if not is_viewer_ready():
        return

    color = OP_COLORS.get("output", Colors.DIM + Colors.WHITE)

    # Send a result header
    send_to_viewer(f"echo '{color}── Result ──{Colors.RESET}'")

    lines = output.strip().split("\n")
    displayed_lines = 0

    for line in lines:
        if displayed_lines >= max_lines:
            remaining = len(lines) - displayed_lines
            send_to_viewer(f"echo '{color}   ... ({remaining} more lines){Colors.RESET}'")
            break

        if line.strip():
            # Escape single quotes for echo command
            safe_line = line.strip()[:100].replace("'", "'\"'\"'")
            send_to_viewer(f"echo '{color}   {safe_line}{Colors.RESET}'")
            displayed_lines += 1


def echo_session_info(session_id: int, session_data: dict) -> None:
    """
    Echo detailed session information to the viewer.

    Args:
        session_id: The session ID
        session_data: Dict containing session details from MSF RPC
    """
    if not is_viewer_ready():
        return

    color = OP_COLORS.get("session", Colors.GREEN)

    send_to_viewer(f"echo '{color}{'─' * 40}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  SESSION {session_id} ESTABLISHED{Colors.RESET}'")

    # Extract key session info
    session_type = session_data.get("type", "unknown")
    target_host = session_data.get("target_host", session_data.get("session_host", "unknown"))
    via_exploit = session_data.get("via_exploit", "")

    send_to_viewer(f"echo '{color}  Type: {session_type}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Target: {target_host}{Colors.RESET}'")
    if via_exploit:
        send_to_viewer(f"echo '{color}  Via: {via_exploit}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}{'─' * 40}{Colors.RESET}'")
