"""
Sliver Visual Terminal Viewer

Opens sliver-client in a separate terminal window and displays Sliver
operations as they occur via the gRPC API, allowing users to learn and
verify actions in real-time.

This mirrors the MSF viewer functionality for Sliver C2.

Workflow:
1. User confirms action in SploitGPT TUI
2. LLM executes via Sliver gRPC
3. Viewer shows equivalent sliver-client command + output

To disable:
  - Set SPLOITGPT_SLIVER_VIEWER_ENABLED=false in .env
"""

import logging
import os
import pty
import select
import shutil
import subprocess
import threading
import time

logger = logging.getLogger(__name__)


# =============================================================================
# ANSI Color Codes for Visual Distinction
# =============================================================================
class Colors:
    """ANSI escape codes for terminal colors."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Operation type colors (slightly different palette from MSF for distinction)
    RED = "\033[91m"  # Kill/destructive operations
    ORANGE = "\033[38;5;208m"  # Implant generation
    YELLOW = "\033[93m"  # Listeners/Jobs
    GREEN = "\033[92m"  # Sessions - success/active
    CYAN = "\033[96m"  # Beacons - async operations
    MAGENTA = "\033[95m"  # Post-exploitation
    BLUE = "\033[94m"  # General commands
    WHITE = "\033[97m"  # Output/results
    GRAY = "\033[90m"  # Separators/banners


# Operation type to color mapping
OP_COLORS = {
    "session": Colors.GREEN,
    "beacon": Colors.CYAN,
    "listener": Colors.YELLOW,
    "job": Colors.YELLOW,
    "implant": Colors.ORANGE,
    "generate": Colors.ORANGE,
    "execute": Colors.MAGENTA,
    "post": Colors.MAGENTA,
    "kill": Colors.RED,
    "general": Colors.BLUE,
    "info": Colors.WHITE,
    "output": Colors.DIM + Colors.WHITE,
    "separator": Colors.GRAY,
}


# Module-level state
_viewer_process: subprocess.Popen | None = None
_viewer_opened_once: bool = False
_pty_master_fd: int | None = None
_viewer_ready: bool = False
_viewer_lock = threading.Lock()
_last_operation_type: str | None = None


def _has_display() -> bool:
    """Check if a display server is available (X11 or Wayland)."""
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _get_desktop_terminal() -> str | None:
    """Get the preferred terminal for the current desktop environment."""
    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").lower()

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

    return None


def _find_terminal() -> str | None:
    """Find an available terminal emulator on the system."""
    desktop_term = _get_desktop_terminal()
    if desktop_term:
        return desktop_term

    terminals = [
        "gnome-terminal",
        "konsole",
        "xfce4-terminal",
        "mate-terminal",
        "tilix",
        "terminator",
        "alacritty",
        "kitty",
        "xterm",
    ]

    for term in terminals:
        if shutil.which(term):
            return term

    return None


def _get_intro_banner() -> str:
    """Generate the intro banner shown when viewer opens."""
    return f"""{Colors.GRAY}
{"=" * 70}
{Colors.BOLD}{Colors.CYAN}  SploitGPT Sliver Viewer - Real-Time Learning Mode{Colors.RESET}{Colors.GRAY}
{"=" * 70}

  You are watching SploitGPT's Sliver C2 operations in real-time.
  
  What you'll see:
  {Colors.GREEN}GREEN{Colors.GRAY}   = Interactive sessions (real-time shell access)
  {Colors.CYAN}CYAN{Colors.GRAY}    = Beacons (async check-in implants)
  {Colors.YELLOW}YELLOW{Colors.GRAY}  = Listeners/Jobs (C2 infrastructure)
  {Colors.ORANGE}ORANGE{Colors.GRAY}  = Implant generation
  {Colors.MAGENTA}MAGENTA{Colors.GRAY} = Post-exploitation commands
  {Colors.RED}RED{Colors.GRAY}     = Kill/cleanup operations
  {Colors.BLUE}BLUE{Colors.GRAY}    = General commands

  Commands shown here mirror what the AI executes via gRPC.
  This is a READ-ONLY view for monitoring and learning.
  
{"=" * 70}{Colors.RESET}
"""


def _build_terminal_command(terminal: str, slave_name: str) -> list[str]:
    """Build the command to open a terminal connected to our PTY slave."""
    title = "SploitGPT Sliver Viewer"

    # Simple shell that displays our commands
    # Since we're echoing gRPC operations (not running sliver-client directly),
    # we just need a shell to display our echo commands
    connect_cmd = f"bash < {slave_name}; echo '[Sliver Viewer] Closed'; cat"

    if terminal == "gnome-terminal":
        return ["gnome-terminal", f"--title={title}", "--", "bash", "-c", connect_cmd]
    elif terminal == "konsole":
        return ["konsole", f"--title={title}", "-e", "bash", "-c", connect_cmd]
    elif terminal == "xfce4-terminal":
        return ["xfce4-terminal", f"--title={title}", "-x", "bash", "-c", connect_cmd]
    elif terminal == "mate-terminal":
        return ["mate-terminal", f"--title={title}", "-x", "bash", "-c", connect_cmd]
    elif terminal == "tilix":
        return ["tilix", f"--title={title}", "-e", "bash", "-c", connect_cmd]
    elif terminal == "terminator":
        return ["terminator", f"--title={title}", "-x", "bash", "-c", connect_cmd]
    elif terminal == "alacritty":
        return ["alacritty", "--title", title, "-e", "bash", "-c", connect_cmd]
    elif terminal == "kitty":
        return ["kitty", "--title", title, "bash", "-c", connect_cmd]
    else:
        return ["xterm", "-title", title, "-e", "bash", "-c", connect_cmd]


def is_viewer_open() -> bool:
    """Check if the Sliver viewer terminal is currently open."""
    global _viewer_process

    if _viewer_process is None:
        return False

    return _viewer_process.poll() is None


def is_viewer_ready() -> bool:
    """Check if the viewer is ready to receive commands."""
    return _viewer_ready and is_viewer_open()


def open_sliver_viewer(*, force: bool = False) -> bool:
    """
    Open a Sliver viewer terminal.

    Args:
        force: If True, open even if already opened once this session.

    Returns:
        True if viewer was opened (or already open), False on failure.
    """
    global _viewer_process, _viewer_opened_once, _pty_master_fd, _viewer_ready

    with _viewer_lock:
        if is_viewer_open():
            logger.debug("Sliver viewer already open")
            return True

        if _viewer_opened_once and not force:
            logger.debug("Sliver viewer was closed by user, not reopening")
            return False

        if not _has_display():
            logger.debug("No display available, skipping Sliver viewer")
            return False

        terminal = _find_terminal()
        if not terminal:
            logger.warning("No terminal emulator found for Sliver viewer")
            return False

        try:
            master_fd, slave_fd = pty.openpty()
            slave_name = os.ttyname(slave_fd)
            _pty_master_fd = master_fd
            _slave_fd_temp = slave_fd

        except Exception as e:
            logger.error(f"Failed to create PTY: {e}")
            return False

        cmd = _build_terminal_command(terminal, slave_name)

        try:
            logger.info(f"Opening Sliver viewer with {terminal}")
            _viewer_process = subprocess.Popen(
                cmd,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _viewer_opened_once = True

            try:
                os.close(_slave_fd_temp)
            except Exception:
                pass

            def _wait_for_ready():
                global _viewer_ready
                time.sleep(1)  # Give terminal time to initialize
                _viewer_ready = True
                _send_intro_banner()

            threading.Thread(target=_wait_for_ready, daemon=True).start()

            return True

        except Exception as e:
            logger.error(f"Failed to open Sliver viewer: {e}")
            if _pty_master_fd:
                os.close(_pty_master_fd)
                _pty_master_fd = None
            return False


def send_to_viewer(command: str) -> bool:
    """
    Send a command to the Sliver viewer terminal.

    Args:
        command: The command/text to display

    Returns:
        True if sent successfully, False if viewer not available.
    """
    global _pty_master_fd

    if not is_viewer_ready():
        return False

    if _pty_master_fd is None:
        return False

    try:
        cmd_bytes = (command + "\n").encode("utf-8")
        os.write(_pty_master_fd, cmd_bytes)
        return True

    except OSError as e:
        logger.debug(f"Failed to write to viewer PTY: {e}")
        return False


def _send_intro_banner() -> None:
    """Send the intro banner to the viewer after it's ready."""
    if not is_viewer_ready():
        return

    banner = _get_intro_banner()
    for line in banner.split("\n"):
        safe_line = line.replace("'", "'\"'\"'")
        send_to_viewer(f"echo '{safe_line}'")
        time.sleep(0.01)


def send_separator(operation_type: str | None = None) -> None:
    """Send a visual separator between different operations."""
    global _last_operation_type

    if not is_viewer_ready():
        return

    if operation_type and operation_type != _last_operation_type:
        color = OP_COLORS.get("separator", Colors.GRAY)
        send_to_viewer(f"echo '{color}{'─' * 50}{Colors.RESET}'")
        _last_operation_type = operation_type


def close_sliver_viewer() -> bool:
    """Close the Sliver viewer terminal if open."""
    global _viewer_process, _pty_master_fd, _viewer_ready

    with _viewer_lock:
        if not is_viewer_open():
            return False

        _viewer_ready = False

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
            logger.warning(f"Error closing Sliver viewer: {e}")
            try:
                _viewer_process.kill()
                _viewer_process = None
            except Exception:
                pass
            return True


# =============================================================================
# gRPC Operation Display Functions
# =============================================================================


def ensure_viewer_open() -> bool:
    """Ensure the Sliver viewer is open if enabled."""
    if is_viewer_open():
        return True

    try:
        from sploitgpt.core.config import get_settings

        settings = get_settings()
        if not getattr(settings, "sliver_viewer_enabled", False):
            return False
    except Exception:
        return False

    return open_sliver_viewer()


def echo_connection(host: str, port: int, version: str) -> None:
    """Echo Sliver connection info to viewer."""
    ensure_viewer_open()

    if not is_viewer_ready():
        return

    color = Colors.GREEN
    send_to_viewer(f"echo '{color}{'─' * 40}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  CONNECTED TO SLIVER SERVER{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Host: {host}:{port}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Version: {version}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}{'─' * 40}{Colors.RESET}'")


def echo_operation(operation: str, op_type: str = "general", details: dict | None = None) -> None:
    """
    Echo a Sliver operation to the viewer.

    Args:
        operation: Description of the operation
        op_type: Type of operation for color coding
        details: Optional dict of key-value pairs to display
    """
    ensure_viewer_open()

    if not is_viewer_ready():
        return

    send_separator(op_type)

    color = OP_COLORS.get(op_type, Colors.WHITE)
    send_to_viewer(f"echo '{color}[{op_type.upper()}] {operation}{Colors.RESET}'")

    if details:
        for key, value in details.items():
            send_to_viewer(f"echo '{color}  {key}: {value}{Colors.RESET}'")


def echo_sessions(sessions: list, beacons: list | None = None) -> None:
    """Echo session/beacon list to viewer."""
    if not is_viewer_ready():
        return

    send_separator("session")

    if sessions:
        color = OP_COLORS.get("session", Colors.GREEN)
        send_to_viewer(f"echo '{color}SESSIONS ({len(sessions)}){Colors.RESET}'")
        for s in sessions[:10]:  # Limit display
            name = getattr(
                s, "name", s.get("name", "unknown") if isinstance(s, dict) else "unknown"
            )
            hostname = getattr(
                s, "hostname", s.get("hostname", "?") if isinstance(s, dict) else "?"
            )
            sid = getattr(s, "id", s.get("id", "?") if isinstance(s, dict) else "?")
            send_to_viewer(f"echo '{color}  [{sid[:8]}] {name} @ {hostname}{Colors.RESET}'")

    if beacons:
        color = OP_COLORS.get("beacon", Colors.CYAN)
        send_to_viewer(f"echo '{color}BEACONS ({len(beacons)}){Colors.RESET}'")
        for b in beacons[:10]:
            name = getattr(
                b, "name", b.get("name", "unknown") if isinstance(b, dict) else "unknown"
            )
            hostname = getattr(
                b, "hostname", b.get("hostname", "?") if isinstance(b, dict) else "?"
            )
            bid = getattr(b, "id", b.get("id", "?") if isinstance(b, dict) else "?")
            send_to_viewer(f"echo '{color}  [{bid[:8]}] {name} @ {hostname}{Colors.RESET}'")


def echo_jobs(jobs: list) -> None:
    """Echo jobs/listeners list to viewer."""
    if not is_viewer_ready():
        return

    send_separator("job")

    color = OP_COLORS.get("job", Colors.YELLOW)
    send_to_viewer(f"echo '{color}JOBS ({len(jobs)}){Colors.RESET}'")

    for j in jobs[:10]:
        name = getattr(j, "name", j.get("name", "?") if isinstance(j, dict) else "?")
        port = getattr(j, "port", j.get("port", "?") if isinstance(j, dict) else "?")
        protocol = getattr(j, "protocol", j.get("protocol", "?") if isinstance(j, dict) else "?")
        send_to_viewer(f"echo '{color}  [{name}] {protocol}:{port}{Colors.RESET}'")


def echo_execute(session_or_beacon_id: str, command: str, args: list | None = None) -> None:
    """Echo command execution to viewer."""
    if not is_viewer_ready():
        return

    send_separator("execute")

    color = OP_COLORS.get("execute", Colors.MAGENTA)
    cmd_str = f"{command} {' '.join(args or [])}"
    send_to_viewer(f"echo '{color}[EXECUTE] {session_or_beacon_id[:8]}> {cmd_str}{Colors.RESET}'")


def echo_output(output: str, max_lines: int = 15) -> None:
    """Echo command output to viewer."""
    if not output or not output.strip():
        return

    if not is_viewer_ready():
        return

    color = OP_COLORS.get("output", Colors.DIM + Colors.WHITE)
    send_to_viewer(f"echo '{color}── Output ──{Colors.RESET}'")

    lines = output.strip().split("\n")
    for i, line in enumerate(lines[:max_lines]):
        safe_line = line[:100].replace("'", "'\"'\"'")
        send_to_viewer(f"echo '{color}  {safe_line}{Colors.RESET}'")

    if len(lines) > max_lines:
        remaining = len(lines) - max_lines
        send_to_viewer(f"echo '{color}  ... ({remaining} more lines){Colors.RESET}'")


def echo_implant_generated(name: str, os: str, arch: str, is_beacon: bool) -> None:
    """Echo implant generation to viewer."""
    if not is_viewer_ready():
        return

    send_separator("generate")

    color = OP_COLORS.get("generate", Colors.ORANGE)
    implant_type = "BEACON" if is_beacon else "SESSION"
    send_to_viewer(f"echo '{color}{'─' * 40}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  IMPLANT GENERATED{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Name: {name}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Type: {implant_type}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Target: {os}/{arch}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}{'─' * 40}{Colors.RESET}'")


def echo_listener_started(job_id: int, protocol: str, host: str, port: int) -> None:
    """Echo listener start to viewer."""
    if not is_viewer_ready():
        return

    send_separator("listener")

    color = OP_COLORS.get("listener", Colors.YELLOW)
    send_to_viewer(f"echo '{color}{'─' * 40}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  LISTENER STARTED{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Job ID: {job_id}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Protocol: {protocol}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Binding: {host}:{port}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}{'─' * 40}{Colors.RESET}'")


def echo_new_session(session_id: str, name: str, hostname: str, username: str, os: str) -> None:
    """Echo new session callback to viewer."""
    if not is_viewer_ready():
        return

    send_separator("session")

    color = OP_COLORS.get("session", Colors.GREEN)
    send_to_viewer(f"echo '{color}{'─' * 40}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  NEW SESSION ESTABLISHED{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  ID: {session_id[:16]}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Name: {name}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Host: {username}@{hostname}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  OS: {os}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}{'─' * 40}{Colors.RESET}'")


def echo_new_beacon(beacon_id: str, name: str, hostname: str, username: str, interval: int) -> None:
    """Echo new beacon callback to viewer."""
    if not is_viewer_ready():
        return

    send_separator("beacon")

    color = OP_COLORS.get("beacon", Colors.CYAN)
    send_to_viewer(f"echo '{color}{'─' * 40}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  NEW BEACON REGISTERED{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  ID: {beacon_id[:16]}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Name: {name}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Host: {username}@{hostname}{Colors.RESET}'")
    send_to_viewer(f"echo '{color}  Interval: {interval}s{Colors.RESET}'")
    send_to_viewer(f"echo '{color}{'─' * 40}{Colors.RESET}'")
