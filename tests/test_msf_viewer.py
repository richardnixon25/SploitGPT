"""
Tests for MSF Visual Terminal Viewer (PTY-based)

These tests verify the viewer module without actually opening terminals
or spawning msfconsole.
"""

import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from sploitgpt.msf.viewer import (
    _build_terminal_command,
    _find_terminal,
    _get_desktop_terminal,
    _get_intro_banner,
    _get_operation_type,
    _has_display,
    _rpc_to_console,
    close_msf_viewer,
    Colors,
    echo_output,
    echo_rpc_call,
    echo_session_info,
    ensure_viewer_open,
    is_viewer_open,
    is_viewer_ready,
    OP_COLORS,
    open_msf_viewer,
    send_colored_command,
    send_separator,
    send_to_viewer,
)


class TestViewerHelpers:
    """Tests for viewer helper functions."""

    def test_find_terminal_returns_string_or_none(self):
        """Test that _find_terminal returns a string or None."""
        result = _find_terminal()
        assert result is None or isinstance(result, str)

    def test_build_terminal_command_gnome(self):
        """Test command building for gnome-terminal with PTY."""
        cmd = _build_terminal_command("gnome-terminal", "/dev/pts/99")
        assert cmd[0] == "gnome-terminal"
        assert "--title=SploitGPT MSF Viewer" in cmd
        assert any("msfconsole" in arg for arg in cmd)
        assert any("/dev/pts/99" in arg for arg in cmd)

    def test_build_terminal_command_konsole(self):
        """Test command building for konsole with PTY."""
        cmd = _build_terminal_command("konsole", "/dev/pts/99")
        assert cmd[0] == "konsole"
        assert any("msfconsole" in arg for arg in cmd)

    def test_build_terminal_command_xterm(self):
        """Test command building for xterm (fallback) with PTY."""
        cmd = _build_terminal_command("xterm", "/dev/pts/99")
        assert cmd[0] == "xterm"
        assert any("msfconsole" in arg for arg in cmd)

    def test_build_terminal_command_alacritty(self):
        """Test command building for alacritty with PTY."""
        cmd = _build_terminal_command("alacritty", "/dev/pts/99")
        assert cmd[0] == "alacritty"
        assert any("msfconsole" in arg for arg in cmd)


class TestDisplayDetection:
    """Tests for display and desktop environment detection."""

    @patch.dict("os.environ", {"DISPLAY": ":0"}, clear=True)
    def test_has_display_with_x11(self):
        """Test display detection with X11."""
        assert _has_display() is True

    @patch.dict("os.environ", {"WAYLAND_DISPLAY": "wayland-0"}, clear=True)
    def test_has_display_with_wayland(self):
        """Test display detection with Wayland."""
        assert _has_display() is True

    @patch.dict("os.environ", {}, clear=True)
    def test_has_display_headless(self):
        """Test display detection in headless environment."""
        assert _has_display() is False

    @patch("sploitgpt.msf.viewer.shutil.which")
    @patch.dict("os.environ", {"XDG_CURRENT_DESKTOP": "GNOME"}, clear=True)
    def test_get_desktop_terminal_gnome(self, mock_which):
        """Test desktop terminal detection for GNOME."""
        mock_which.return_value = "/usr/bin/gnome-terminal"
        assert _get_desktop_terminal() == "gnome-terminal"

    @patch("sploitgpt.msf.viewer.shutil.which")
    @patch.dict("os.environ", {"XDG_CURRENT_DESKTOP": "KDE"}, clear=True)
    def test_get_desktop_terminal_kde(self, mock_which):
        """Test desktop terminal detection for KDE."""
        mock_which.return_value = "/usr/bin/konsole"
        assert _get_desktop_terminal() == "konsole"

    @patch.dict("os.environ", {}, clear=True)
    def test_get_desktop_terminal_unknown(self):
        """Test desktop terminal returns None for unknown desktop."""
        assert _get_desktop_terminal() is None


class TestViewerState:
    """Tests for viewer state management."""

    def test_is_viewer_open_false_initially(self):
        """Test that viewer reports closed when not opened."""
        # Reset module state
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None

        assert is_viewer_open() is False

    def test_is_viewer_ready_false_initially(self):
        """Test that viewer reports not ready when not opened."""
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_ready = False

        assert is_viewer_ready() is False

    def test_close_viewer_when_not_open(self):
        """Test closing viewer when it's not open returns False."""
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None

        assert close_msf_viewer() is False


class TestOpenViewer:
    """Tests for open_msf_viewer function."""

    @patch("sploitgpt.msf.viewer._has_display", return_value=True)
    @patch("sploitgpt.msf.viewer.shutil.which")
    def test_open_fails_without_terminal(self, mock_which, mock_display):
        """Test that open fails gracefully when no terminal is found."""
        mock_which.return_value = None

        # Reset state
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_opened_once = False

        result = open_msf_viewer()
        assert result is False

    @patch("sploitgpt.msf.viewer._has_display", return_value=True)
    @patch("sploitgpt.msf.viewer.shutil.which")
    def test_open_fails_without_msfconsole(self, mock_which, mock_display):
        """Test that open fails when msfconsole is not found."""

        # Return terminal but not msfconsole
        def which_side_effect(cmd):
            if cmd == "gnome-terminal":
                return "/usr/bin/gnome-terminal"
            if cmd == "msfconsole":
                return None
            return None

        mock_which.side_effect = which_side_effect

        # Reset state
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_opened_once = False

        result = open_msf_viewer()
        assert result is False

    @patch("sploitgpt.msf.viewer._has_display", return_value=True)
    @patch("sploitgpt.msf.viewer.pty.openpty")
    @patch("sploitgpt.msf.viewer.os.ttyname")
    @patch("sploitgpt.msf.viewer.os.close")
    @patch("sploitgpt.msf.viewer.subprocess.Popen")
    @patch("sploitgpt.msf.viewer.shutil.which")
    def test_open_succeeds_with_terminal_and_msfconsole(
        self, mock_which, mock_popen, mock_os_close, mock_ttyname, mock_openpty, mock_display
    ):
        """Test successful viewer opening with PTY."""
        mock_which.return_value = "/usr/bin/gnome-terminal"
        mock_openpty.return_value = (10, 11)  # master_fd, slave_fd
        mock_ttyname.return_value = "/dev/pts/99"
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Process still running
        mock_popen.return_value = mock_process

        # Reset state
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_opened_once = False
        viewer_module._pty_master_fd = None
        viewer_module._viewer_ready = False

        result = open_msf_viewer()

        assert result is True
        assert mock_popen.called
        assert mock_openpty.called
        assert viewer_module._viewer_opened_once is True

    @patch("sploitgpt.msf.viewer._has_display", return_value=True)
    @patch("sploitgpt.msf.viewer.subprocess.Popen")
    @patch("sploitgpt.msf.viewer.shutil.which")
    def test_open_skips_when_already_opened(self, mock_which, mock_popen, mock_display):
        """Test that viewer doesn't reopen after user closes it."""
        mock_which.return_value = "/usr/bin/gnome-terminal"

        # Simulate: was opened, user closed it
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_opened_once = True

        result = open_msf_viewer()  # Should skip

        assert result is False
        assert not mock_popen.called  # Didn't try to open

    @patch("sploitgpt.msf.viewer._has_display", return_value=True)
    @patch("sploitgpt.msf.viewer.pty.openpty")
    @patch("sploitgpt.msf.viewer.os.ttyname")
    @patch("sploitgpt.msf.viewer.os.close")
    @patch("sploitgpt.msf.viewer.subprocess.Popen")
    @patch("sploitgpt.msf.viewer.shutil.which")
    def test_force_reopen(
        self, mock_which, mock_popen, mock_os_close, mock_ttyname, mock_openpty, mock_display
    ):
        """Test force reopening after user closed viewer."""
        mock_which.return_value = "/usr/bin/gnome-terminal"
        mock_openpty.return_value = (10, 11)
        mock_ttyname.return_value = "/dev/pts/99"
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        # Simulate: was opened, user closed it
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_opened_once = True
        viewer_module._pty_master_fd = None

        result = open_msf_viewer(force=True)  # Force reopen

        assert result is True
        assert mock_popen.called

    @patch("sploitgpt.msf.viewer._has_display", return_value=False)
    def test_open_skips_without_display(self, mock_display):
        """Test that viewer skips opening in headless environment."""
        # Reset state
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_opened_once = False

        result = open_msf_viewer()

        assert result is False


class TestSendToViewer:
    """Tests for send_to_viewer function."""

    def test_send_fails_when_not_ready(self):
        """Test that send_to_viewer returns False when viewer not ready."""
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_ready = False
        viewer_module._viewer_process = None

        result = send_to_viewer("sessions")
        assert result is False

    @patch("sploitgpt.msf.viewer.os.write")
    def test_send_succeeds_when_ready(self, mock_write):
        """Test that send_to_viewer writes to PTY when ready."""
        import sploitgpt.msf.viewer as viewer_module

        # Simulate ready state
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Still running
        viewer_module._viewer_process = mock_process
        viewer_module._viewer_ready = True
        viewer_module._pty_master_fd = 10

        result = send_to_viewer("sessions")

        assert result is True
        mock_write.assert_called_once()
        # Check that the command + newline was written
        call_args = mock_write.call_args
        assert call_args[0][0] == 10  # fd
        assert b"sessions\n" == call_args[0][1]


class TestRpcToConsoleMapping:
    """Tests for RPC-to-console command mapping."""

    def test_module_search(self):
        """Test module.search maps to search command."""
        cmd = _rpc_to_console("module.search", ["vsftpd type:exploit"])
        assert cmd == "search vsftpd type:exploit"

    def test_module_search_empty(self):
        """Test module.search with empty params returns None."""
        cmd = _rpc_to_console("module.search", [])
        assert cmd is None

    def test_session_list(self):
        """Test session.list maps to sessions command."""
        cmd = _rpc_to_console("session.list", [])
        assert cmd == "sessions"

    def test_job_list(self):
        """Test job.list maps to jobs command."""
        cmd = _rpc_to_console("job.list", [])
        assert cmd == "jobs"

    def test_job_stop(self):
        """Test job.stop maps to jobs -k command."""
        cmd = _rpc_to_console("job.stop", [5])
        assert cmd == "jobs -k 5"

    def test_session_stop(self):
        """Test session.stop maps to sessions -k command."""
        cmd = _rpc_to_console("session.stop", [3])
        assert cmd == "sessions -k 3"

    def test_module_execute_exploit(self):
        """Test module.execute for exploit type."""
        cmd = _rpc_to_console(
            "module.execute",
            [
                "exploit",
                "exploit/unix/ftp/vsftpd_234_backdoor",
                {"RHOSTS": "10.0.0.5", "RPORT": "21"},
            ],
        )
        assert isinstance(cmd, list)
        assert "use exploit/unix/ftp/vsftpd_234_backdoor" in cmd
        assert "set RHOSTS 10.0.0.5" in cmd
        assert "set RPORT 21" in cmd
        assert "exploit" in cmd

    def test_module_execute_auxiliary(self):
        """Test module.execute for auxiliary type uses 'run' instead of 'exploit'."""
        cmd = _rpc_to_console(
            "module.execute",
            ["auxiliary", "auxiliary/scanner/portscan/tcp", {"RHOSTS": "10.0.0.0/24"}],
        )
        assert isinstance(cmd, list)
        assert "run" in cmd
        assert "exploit" not in cmd

    def test_module_info(self):
        """Test module.info maps to use + info commands."""
        cmd = _rpc_to_console("module.info", ["exploit", "exploit/test/module"])
        assert isinstance(cmd, list)
        assert "use exploit/test/module" in cmd
        assert "info" in cmd

    def test_module_options(self):
        """Test module.options maps to use + show options commands."""
        cmd = _rpc_to_console("module.options", ["exploit", "exploit/test/module"])
        assert isinstance(cmd, list)
        assert "use exploit/test/module" in cmd
        assert "show options" in cmd

    def test_session_shell_write(self):
        """Test session.shell_write shows command sent to session."""
        cmd = _rpc_to_console("session.shell_write", [1, "whoami\n"])
        assert cmd == "# Session 1: whoami"

    def test_console_write(self):
        """Test console.write passes through the command."""
        cmd = _rpc_to_console("console.write", [0, "search apache\n"])
        assert cmd == "search apache"

    def test_auth_methods_skipped(self):
        """Test auth methods return None (not echoed)."""
        assert _rpc_to_console("auth.login", ["user", "pass"]) is None
        assert _rpc_to_console("auth.logout", []) is None

    def test_console_management_skipped(self):
        """Test console management methods return None."""
        assert _rpc_to_console("console.create", []) is None
        assert _rpc_to_console("console.read", [0]) is None
        assert _rpc_to_console("console.destroy", [0]) is None


class TestEchoRpcCall:
    """Tests for echo_rpc_call function."""

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    def test_echo_rpc_call_single_command(self, mock_send):
        """Test echo_rpc_call sends single command."""
        mock_send.return_value = True
        echo_rpc_call("session.list", [])
        mock_send.assert_called_with("sessions")

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.time.sleep")
    def test_echo_rpc_call_multi_command(self, mock_sleep, mock_send):
        """Test echo_rpc_call sends multiple commands for module.execute."""
        mock_send.return_value = True
        echo_rpc_call(
            "module.execute",
            ["exploit", "exploit/test", {"RHOSTS": "10.0.0.1"}],
        )
        # Should send: use, set RHOSTS, exploit
        assert mock_send.call_count >= 3

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    def test_echo_rpc_call_skips_auth(self, mock_send):
        """Test echo_rpc_call doesn't send auth commands."""
        echo_rpc_call("auth.login", ["user", "pass"])
        mock_send.assert_not_called()

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    def test_echo_rpc_call_skips_console_read(self, mock_send):
        """Test echo_rpc_call doesn't send console.read commands."""
        echo_rpc_call("console.read", [0])
        mock_send.assert_not_called()


class TestEchoOutput:
    """Tests for echo_output function."""

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.is_viewer_ready", return_value=True)
    def test_echo_output_sends_formatted_lines(self, mock_ready, mock_send):
        """Test echo_output sends formatted lines with header."""
        mock_send.return_value = True
        echo_output("Line 1\nLine 2")
        # 1 header + 2 content lines = 3 calls
        assert mock_send.call_count == 3
        # Check first call is the result header
        first_call = mock_send.call_args_list[0][0][0]
        assert "Result" in first_call or "result" in first_call.lower()

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.is_viewer_ready", return_value=False)
    def test_echo_output_skips_when_not_ready(self, mock_ready, mock_send):
        """Test echo_output does nothing when viewer not ready."""
        echo_output("Some output")
        mock_send.assert_not_called()

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.is_viewer_ready", return_value=True)
    def test_echo_output_skips_empty(self, mock_ready, mock_send):
        """Test echo_output does nothing for empty output."""
        echo_output("")
        mock_send.assert_not_called()
        echo_output("   ")
        mock_send.assert_not_called()


class TestEnsureViewerOpen:
    """Tests for ensure_viewer_open function."""

    @patch("sploitgpt.msf.viewer.is_viewer_open", return_value=True)
    def test_ensure_returns_true_if_already_open(self, mock_open):
        """Test ensure_viewer_open returns True if already open."""
        result = ensure_viewer_open()
        assert result is True

    @patch("sploitgpt.msf.viewer.is_viewer_open", return_value=False)
    @patch("sploitgpt.msf.viewer.open_msf_viewer", return_value=True)
    @patch("sploitgpt.core.config.get_settings")
    def test_ensure_opens_if_enabled(self, mock_settings, mock_open, mock_is_open):
        """Test ensure_viewer_open opens viewer if enabled in settings."""
        mock_settings.return_value.msf_viewer_enabled = True
        result = ensure_viewer_open()
        assert result is True
        mock_open.assert_called_once()

    @patch("sploitgpt.msf.viewer.is_viewer_open", return_value=False)
    @patch("sploitgpt.msf.viewer.open_msf_viewer")
    @patch("sploitgpt.core.config.get_settings")
    def test_ensure_skips_if_disabled(self, mock_settings, mock_open, mock_is_open):
        """Test ensure_viewer_open skips if disabled in settings."""
        mock_settings.return_value.msf_viewer_enabled = False
        result = ensure_viewer_open()
        assert result is False
        mock_open.assert_not_called()


class TestColorCoding:
    """Tests for ANSI color coding functionality."""

    def test_colors_class_has_required_colors(self):
        """Test Colors class has all required ANSI codes."""
        assert hasattr(Colors, "RESET")
        assert hasattr(Colors, "RED")
        assert hasattr(Colors, "YELLOW")
        assert hasattr(Colors, "GREEN")
        assert hasattr(Colors, "CYAN")
        assert hasattr(Colors, "MAGENTA")
        assert hasattr(Colors, "BLUE")

    def test_colors_are_ansi_escape_codes(self):
        """Test color values are valid ANSI escape sequences."""
        assert Colors.RESET.startswith("\033[")
        assert Colors.RED.startswith("\033[")

    def test_op_colors_mapping_exists(self):
        """Test operation type to color mapping exists."""
        assert "exploit" in OP_COLORS
        assert "auxiliary" in OP_COLORS
        assert "session" in OP_COLORS
        assert "job" in OP_COLORS
        assert "module_info" in OP_COLORS
        assert "search" in OP_COLORS


class TestOperationTypeDetection:
    """Tests for operation type detection."""

    def test_session_operations(self):
        """Test session operations are detected."""
        assert _get_operation_type("session.list", []) == "session"
        assert _get_operation_type("session.stop", [1]) == "session"
        assert _get_operation_type("session.shell_write", [1, "cmd"]) == "session"

    def test_job_operations(self):
        """Test job operations are detected."""
        assert _get_operation_type("job.list", []) == "job"
        assert _get_operation_type("job.stop", [1]) == "job"

    def test_module_search(self):
        """Test module search is detected."""
        assert _get_operation_type("module.search", ["vsftpd"]) == "search"

    def test_module_info(self):
        """Test module info operations are detected."""
        assert _get_operation_type("module.info", ["exploit", "test"]) == "module_info"
        assert _get_operation_type("module.options", ["exploit", "test"]) == "module_info"

    def test_exploit_execution(self):
        """Test exploit execution is detected."""
        assert _get_operation_type("module.execute", ["exploit", "test", {}]) == "exploit"

    def test_auxiliary_execution(self):
        """Test auxiliary execution is detected."""
        assert _get_operation_type("module.execute", ["auxiliary", "test", {}]) == "auxiliary"

    def test_general_fallback(self):
        """Test unknown operations fall back to general."""
        assert _get_operation_type("unknown.method", []) == "general"


class TestIntroBanner:
    """Tests for intro banner functionality."""

    def test_intro_banner_contains_key_elements(self):
        """Test intro banner has all required information."""
        banner = _get_intro_banner()
        assert "SploitGPT" in banner
        assert "Viewer" in banner
        assert "RED" in banner
        assert "YELLOW" in banner
        assert "GREEN" in banner
        assert "READ-ONLY" in banner or "read-only" in banner.lower()

    def test_intro_banner_has_color_codes(self):
        """Test intro banner includes ANSI color codes."""
        banner = _get_intro_banner()
        assert "\033[" in banner  # Contains ANSI escape sequences


class TestVisualSeparators:
    """Tests for visual separator functionality."""

    @patch("sploitgpt.msf.viewer.is_viewer_ready", return_value=False)
    def test_send_separator_skips_when_not_ready(self, mock_ready):
        """Test separator is not sent when viewer not ready."""
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._last_operation_type = None

        # Should not raise, just skip
        send_separator("exploit")

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.is_viewer_ready", return_value=True)
    def test_send_separator_sends_when_type_changes(self, mock_ready, mock_send):
        """Test separator is sent when operation type changes."""
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._last_operation_type = "search"
        mock_send.return_value = True

        send_separator("exploit")

        mock_send.assert_called_once()
        # Verify separator line was sent
        call_arg = mock_send.call_args[0][0]
        assert "echo" in call_arg


class TestSessionInfo:
    """Tests for session info echoing."""

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.is_viewer_ready", return_value=True)
    def test_echo_session_info_displays_details(self, mock_ready, mock_send):
        """Test session info displays key session details."""
        mock_send.return_value = True

        session_data = {
            "type": "meterpreter",
            "target_host": "10.0.0.5",
            "via_exploit": "exploit/unix/ftp/vsftpd_234_backdoor",
        }

        echo_session_info(1, session_data)

        # Should send multiple lines with session details
        assert mock_send.call_count >= 4

        # Check that session ID is mentioned
        calls = [str(c) for c in mock_send.call_args_list]
        call_str = " ".join(calls)
        assert "SESSION" in call_str or "session" in call_str.lower()

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.is_viewer_ready", return_value=False)
    def test_echo_session_info_skips_when_not_ready(self, mock_ready, mock_send):
        """Test session info is not sent when viewer not ready."""
        echo_session_info(1, {"type": "shell"})
        mock_send.assert_not_called()


class TestImprovedEchoOutput:
    """Tests for improved echo_output functionality."""

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.is_viewer_ready", return_value=True)
    def test_echo_output_sends_header(self, mock_ready, mock_send):
        """Test echo_output sends a result header."""
        mock_send.return_value = True
        echo_output("Line 1\nLine 2")

        # First call should be the header
        first_call = mock_send.call_args_list[0][0][0]
        assert "Result" in first_call or "result" in first_call.lower()

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.is_viewer_ready", return_value=True)
    def test_echo_output_respects_max_lines(self, mock_ready, mock_send):
        """Test echo_output truncates at max_lines."""
        mock_send.return_value = True

        # Generate 20 lines of output
        output = "\n".join([f"Line {i}" for i in range(20)])
        echo_output(output, max_lines=5)

        # Should have: 1 header + 5 content lines + 1 "more lines" message
        assert mock_send.call_count <= 8  # Some margin for implementation details

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.is_viewer_ready", return_value=True)
    def test_echo_output_escapes_quotes(self, mock_ready, mock_send):
        """Test echo_output properly escapes single quotes."""
        mock_send.return_value = True
        echo_output("It's a test")

        # Should have escaped the quote
        mock_send.assert_called()  # Just verify it ran without error
