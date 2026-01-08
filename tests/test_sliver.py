"""
Tests for Sliver C2 Integration

Tests the Sliver client module, tools, and viewer without requiring
an actual Sliver server connection.
"""

import asyncio
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# =============================================================================
# Dataclass Tests
# =============================================================================


class TestSliverSession:
    """Tests for SliverSession dataclass."""

    def test_session_from_pb(self):
        """Test creating SliverSession from protobuf object."""
        from sploitgpt.sliver import SliverSession

        # Create mock protobuf session
        mock_pb = MagicMock()
        mock_pb.ID = "abc123def456"
        mock_pb.Name = "SWEET_LEMUR"
        mock_pb.Hostname = "victim-pc"
        mock_pb.Username = "admin"
        mock_pb.UID = "1000"
        mock_pb.GID = "1000"
        mock_pb.OS = "linux"
        mock_pb.Arch = "amd64"
        mock_pb.Transport = "mtls"
        mock_pb.RemoteAddress = "10.0.0.5:54321"
        mock_pb.PID = 1234
        mock_pb.Filename = "/tmp/implant"
        mock_pb.ActiveC2 = "mtls://10.0.0.1:8888"
        mock_pb.ReconnectInterval = 60
        mock_pb.ProxyURL = ""
        mock_pb.Burned = False
        mock_pb.Extensions = ["seatbelt"]

        session = SliverSession.from_pb(mock_pb)

        assert session.id == "abc123def456"
        assert session.name == "SWEET_LEMUR"
        assert session.hostname == "victim-pc"
        assert session.username == "admin"
        assert session.os == "linux"
        assert session.arch == "amd64"
        assert session.transport == "mtls"
        assert session.pid == 1234
        assert session.extensions == ["seatbelt"]

    def test_session_from_pb_no_extensions(self):
        """Test SliverSession with empty extensions."""
        from sploitgpt.sliver import SliverSession

        mock_pb = MagicMock()
        mock_pb.ID = "abc123"
        mock_pb.Name = "test"
        mock_pb.Hostname = "host"
        mock_pb.Username = "user"
        mock_pb.UID = "1000"
        mock_pb.GID = "1000"
        mock_pb.OS = "windows"
        mock_pb.Arch = "amd64"
        mock_pb.Transport = "http"
        mock_pb.RemoteAddress = "10.0.0.5:80"
        mock_pb.PID = 5678
        mock_pb.Filename = "C:\\implant.exe"
        mock_pb.ActiveC2 = "http://10.0.0.1:80"
        mock_pb.ReconnectInterval = 30
        mock_pb.ProxyURL = ""
        mock_pb.Burned = False
        mock_pb.Extensions = None

        session = SliverSession.from_pb(mock_pb)
        assert session.extensions == []


class TestSliverBeacon:
    """Tests for SliverBeacon dataclass."""

    def test_beacon_from_pb(self):
        """Test creating SliverBeacon from protobuf object."""
        from sploitgpt.sliver import SliverBeacon

        mock_pb = MagicMock()
        mock_pb.ID = "beacon123"
        mock_pb.Name = "SILENT_HAWK"
        mock_pb.Hostname = "target-server"
        mock_pb.Username = "SYSTEM"
        mock_pb.UID = "S-1-5-18"
        mock_pb.GID = "S-1-5-18"
        mock_pb.OS = "windows"
        mock_pb.Arch = "amd64"
        mock_pb.Transport = "https"
        mock_pb.RemoteAddress = "192.168.1.100:443"
        mock_pb.PID = 4444
        mock_pb.Filename = "svchost.exe"
        mock_pb.ActiveC2 = "https://evil.com"
        mock_pb.Interval = 60
        mock_pb.Jitter = 30
        mock_pb.Burned = False
        mock_pb.NextCheckin = 1704067200

        beacon = SliverBeacon.from_pb(mock_pb)

        assert beacon.id == "beacon123"
        assert beacon.name == "SILENT_HAWK"
        assert beacon.interval == 60
        assert beacon.jitter == 30
        assert beacon.os == "windows"


class TestSliverJob:
    """Tests for SliverJob dataclass."""

    def test_job_from_pb(self):
        """Test creating SliverJob from protobuf object."""
        from sploitgpt.sliver import SliverJob

        mock_pb = MagicMock()
        mock_pb.ID = 1
        mock_pb.Name = "mtls"
        mock_pb.Description = "mTLS listener"
        mock_pb.Protocol = "tcp"
        mock_pb.Port = 8888
        mock_pb.Domains = ["c2.example.com"]

        job = SliverJob.from_pb(mock_pb)

        assert job.id == 1
        assert job.name == "mtls"
        assert job.port == 8888
        assert job.domains == ["c2.example.com"]

    def test_job_from_pb_no_domains(self):
        """Test SliverJob with no domains."""
        from sploitgpt.sliver import SliverJob

        mock_pb = MagicMock()
        mock_pb.ID = 2
        mock_pb.Name = "http"
        mock_pb.Description = "HTTP listener"
        mock_pb.Protocol = "tcp"
        mock_pb.Port = 80
        mock_pb.Domains = None

        job = SliverJob.from_pb(mock_pb)
        assert job.domains == []


# =============================================================================
# SliverRPC Client Tests
# =============================================================================


class TestSliverRPCConfigResolution:
    """Tests for config path resolution."""

    def test_resolve_explicit_path(self, tmp_path):
        """Test config resolution with explicit path."""
        from sploitgpt.sliver import SliverRPC

        config_file = tmp_path / "test.cfg"
        config_file.touch()

        client = SliverRPC(config_path=str(config_file))
        assert client.config_path == config_file

    @patch.dict("os.environ", {"SPLOITGPT_SLIVER_CONFIG": "/custom/path.cfg"})
    def test_resolve_from_env(self):
        """Test config resolution from environment variable."""
        from sploitgpt.sliver import SliverRPC

        client = SliverRPC()
        assert str(client.config_path) == "/custom/path.cfg"

    @patch.dict("os.environ", {}, clear=True)
    def test_resolve_default_paths(self, tmp_path):
        """Test config resolution falls back to defaults."""
        from sploitgpt.sliver import SliverRPC

        # Patch Path.exists to return False for all defaults
        with patch("pathlib.Path.exists", return_value=False):
            client = SliverRPC()
            # Should use first default path
            assert "sliver" in str(client.config_path).lower()


class TestSliverRPCConnection:
    """Tests for SliverRPC connection handling."""

    def test_is_connected_false_initially(self):
        """Test client reports not connected initially."""
        from sploitgpt.sliver import SliverRPC

        client = SliverRPC()
        assert client.is_connected is False

    @pytest.mark.asyncio
    async def test_connect_fails_without_config(self, tmp_path):
        """Test connection fails when config file doesn't exist."""
        from sploitgpt.sliver import SliverRPC

        client = SliverRPC(config_path=tmp_path / "nonexistent.cfg")
        result = await client.connect(quiet=True)
        assert result is False

    @pytest.mark.asyncio
    async def test_disconnect_clears_state(self):
        """Test disconnect clears client state."""
        from sploitgpt.sliver import SliverRPC

        client = SliverRPC()
        client._client = MagicMock()
        client._config = MagicMock()

        await client.disconnect()

        assert client._client is None
        assert client._config is None


class TestSliverRPCMethods:
    """Tests for SliverRPC methods with mocked client."""

    @pytest.fixture
    def mock_sliver_client(self):
        """Create a mocked SliverRPC with connected client."""
        from sploitgpt.sliver import SliverRPC

        client = SliverRPC()
        client._client = AsyncMock()
        return client

    @pytest.mark.asyncio
    async def test_version(self, mock_sliver_client):
        """Test version retrieval."""
        mock_version = MagicMock()
        mock_version.Major = 1
        mock_version.Minor = 6
        mock_version.Patch = 1
        mock_version.Commit = "abc123"
        mock_version.CompiledAt = "2024-01-01"
        mock_version.OS = "linux"
        mock_version.Arch = "amd64"

        mock_sliver_client._client.version = AsyncMock(return_value=mock_version)

        result = await mock_sliver_client.version()

        assert result["major"] == 1
        assert result["minor"] == 6
        assert result["patch"] == 1

    @pytest.mark.asyncio
    async def test_list_sessions(self, mock_sliver_client):
        """Test session listing."""
        mock_session = MagicMock()
        mock_session.ID = "sess123"
        mock_session.Name = "TEST"
        mock_session.Hostname = "target"
        mock_session.Username = "admin"
        mock_session.UID = "1000"
        mock_session.GID = "1000"
        mock_session.OS = "linux"
        mock_session.Arch = "amd64"
        mock_session.Transport = "mtls"
        mock_session.RemoteAddress = "10.0.0.5:54321"
        mock_session.PID = 1234
        mock_session.Filename = "/tmp/implant"
        mock_session.ActiveC2 = "mtls://10.0.0.1:8888"
        mock_session.ReconnectInterval = 60
        mock_session.ProxyURL = ""
        mock_session.Burned = False
        mock_session.Extensions = []

        mock_sliver_client._client.sessions = AsyncMock(return_value=[mock_session])

        sessions = await mock_sliver_client.list_sessions()

        assert len(sessions) == 1
        assert sessions[0].id == "sess123"
        assert sessions[0].name == "TEST"

    @pytest.mark.asyncio
    async def test_list_beacons(self, mock_sliver_client):
        """Test beacon listing."""
        mock_beacon = MagicMock()
        mock_beacon.ID = "beacon123"
        mock_beacon.Name = "BEACON_TEST"
        mock_beacon.Hostname = "target"
        mock_beacon.Username = "user"
        mock_beacon.UID = "1000"
        mock_beacon.GID = "1000"
        mock_beacon.OS = "windows"
        mock_beacon.Arch = "amd64"
        mock_beacon.Transport = "https"
        mock_beacon.RemoteAddress = "10.0.0.5:443"
        mock_beacon.PID = 5678
        mock_beacon.Filename = "svchost.exe"
        mock_beacon.ActiveC2 = "https://c2.com"
        mock_beacon.Interval = 60
        mock_beacon.Jitter = 30
        mock_beacon.Burned = False
        mock_beacon.NextCheckin = 1704067200

        mock_sliver_client._client.beacons = AsyncMock(return_value=[mock_beacon])

        beacons = await mock_sliver_client.list_beacons()

        assert len(beacons) == 1
        assert beacons[0].id == "beacon123"
        assert beacons[0].interval == 60

    @pytest.mark.asyncio
    async def test_list_jobs(self, mock_sliver_client):
        """Test job listing."""
        mock_job = MagicMock()
        mock_job.ID = 1
        mock_job.Name = "mtls"
        mock_job.Description = "mTLS listener"
        mock_job.Protocol = "tcp"
        mock_job.Port = 8888
        mock_job.Domains = []

        mock_sliver_client._client.jobs = AsyncMock(return_value=[mock_job])

        jobs = await mock_sliver_client.list_jobs()

        assert len(jobs) == 1
        assert jobs[0].id == 1
        assert jobs[0].port == 8888

    @pytest.mark.asyncio
    async def test_kill_session_success(self, mock_sliver_client):
        """Test successful session kill."""
        mock_sliver_client._client.kill_session = AsyncMock()

        result = await mock_sliver_client.kill_session("sess123")
        assert result is True

    @pytest.mark.asyncio
    async def test_kill_session_failure(self, mock_sliver_client):
        """Test failed session kill."""
        mock_sliver_client._client.kill_session = AsyncMock(side_effect=Exception("Not found"))

        result = await mock_sliver_client.kill_session("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_start_mtls_listener(self, mock_sliver_client):
        """Test starting mTLS listener."""
        mock_result = MagicMock()
        mock_result.JobID = 1

        mock_sliver_client._client.start_mtls_listener = AsyncMock(return_value=mock_result)

        result = await mock_sliver_client.start_mtls_listener(port=8888)

        assert result["job_id"] == 1

    @pytest.mark.asyncio
    async def test_not_connected_raises(self):
        """Test methods raise when not connected."""
        from sploitgpt.sliver import SliverRPC

        client = SliverRPC()
        # _client is None

        with pytest.raises(RuntimeError, match="Not connected"):
            await client.version()


# =============================================================================
# Sliver Viewer Tests
# =============================================================================


class TestSliverViewerHelpers:
    """Tests for Sliver viewer helper functions."""

    def test_has_display_with_x11(self):
        """Test display detection with X11."""
        from sploitgpt.sliver.viewer import _has_display

        with patch.dict("os.environ", {"DISPLAY": ":0"}, clear=True):
            assert _has_display() is True

    def test_has_display_with_wayland(self):
        """Test display detection with Wayland."""
        from sploitgpt.sliver.viewer import _has_display

        with patch.dict("os.environ", {"WAYLAND_DISPLAY": "wayland-0"}, clear=True):
            assert _has_display() is True

    def test_has_display_headless(self):
        """Test display detection in headless environment."""
        from sploitgpt.sliver.viewer import _has_display

        with patch.dict("os.environ", {}, clear=True):
            assert _has_display() is False

    def test_find_terminal_returns_string_or_none(self):
        """Test that _find_terminal returns a string or None."""
        from sploitgpt.sliver.viewer import _find_terminal

        result = _find_terminal()
        assert result is None or isinstance(result, str)

    def test_build_terminal_command_gnome(self):
        """Test command building for gnome-terminal."""
        from sploitgpt.sliver.viewer import _build_terminal_command

        cmd = _build_terminal_command("gnome-terminal", "/dev/pts/99")
        assert cmd[0] == "gnome-terminal"
        assert "--title=SploitGPT Sliver Viewer" in cmd

    def test_build_terminal_command_konsole(self):
        """Test command building for konsole."""
        from sploitgpt.sliver.viewer import _build_terminal_command

        cmd = _build_terminal_command("konsole", "/dev/pts/99")
        assert cmd[0] == "konsole"

    def test_build_terminal_command_xterm_fallback(self):
        """Test command building falls back to xterm."""
        from sploitgpt.sliver.viewer import _build_terminal_command

        cmd = _build_terminal_command("unknown-terminal", "/dev/pts/99")
        assert cmd[0] == "xterm"


class TestSliverViewerColors:
    """Tests for viewer color constants."""

    def test_colors_class_has_required_colors(self):
        """Test Colors class has all required ANSI codes."""
        from sploitgpt.sliver.viewer import Colors

        assert hasattr(Colors, "RESET")
        assert hasattr(Colors, "RED")
        assert hasattr(Colors, "YELLOW")
        assert hasattr(Colors, "GREEN")
        assert hasattr(Colors, "CYAN")
        assert hasattr(Colors, "MAGENTA")
        assert hasattr(Colors, "BLUE")
        assert hasattr(Colors, "ORANGE")

    def test_colors_are_ansi_escape_codes(self):
        """Test color values are valid ANSI escape sequences."""
        from sploitgpt.sliver.viewer import Colors

        assert Colors.RESET.startswith("\033[")
        assert Colors.RED.startswith("\033[")
        assert Colors.ORANGE.startswith("\033[")

    def test_op_colors_mapping_exists(self):
        """Test operation type to color mapping exists."""
        from sploitgpt.sliver.viewer import OP_COLORS

        assert "session" in OP_COLORS
        assert "beacon" in OP_COLORS
        assert "listener" in OP_COLORS
        assert "job" in OP_COLORS
        assert "implant" in OP_COLORS
        assert "execute" in OP_COLORS


class TestSliverViewerState:
    """Tests for viewer state management."""

    def test_is_viewer_open_false_initially(self):
        """Test that viewer reports closed when not opened."""
        import sploitgpt.sliver.viewer as viewer_module

        viewer_module._viewer_process = None
        assert viewer_module.is_viewer_open() is False

    def test_is_viewer_ready_false_initially(self):
        """Test that viewer reports not ready when not opened."""
        import sploitgpt.sliver.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_ready = False
        assert viewer_module.is_viewer_ready() is False

    def test_close_viewer_when_not_open(self):
        """Test closing viewer when it's not open returns False."""
        import sploitgpt.sliver.viewer as viewer_module
        from sploitgpt.sliver.viewer import close_sliver_viewer

        viewer_module._viewer_process = None
        assert close_sliver_viewer() is False


class TestSliverViewerIntroBanner:
    """Tests for intro banner functionality."""

    def test_intro_banner_contains_key_elements(self):
        """Test intro banner has all required information."""
        from sploitgpt.sliver.viewer import _get_intro_banner

        banner = _get_intro_banner()
        assert "SploitGPT" in banner
        assert "Sliver" in banner
        assert "Viewer" in banner
        assert "GREEN" in banner
        assert "CYAN" in banner
        assert "YELLOW" in banner
        assert "READ-ONLY" in banner


class TestSliverViewerSendToViewer:
    """Tests for send_to_viewer function."""

    def test_send_fails_when_not_ready(self):
        """Test that send_to_viewer returns False when viewer not ready."""
        import sploitgpt.sliver.viewer as viewer_module
        from sploitgpt.sliver.viewer import send_to_viewer

        viewer_module._viewer_ready = False
        viewer_module._viewer_process = None

        result = send_to_viewer("test command")
        assert result is False

    @patch("sploitgpt.sliver.viewer.os.write")
    def test_send_succeeds_when_ready(self, mock_write):
        """Test that send_to_viewer writes to PTY when ready."""
        import sploitgpt.sliver.viewer as viewer_module
        from sploitgpt.sliver.viewer import send_to_viewer

        # Simulate ready state
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Still running
        viewer_module._viewer_process = mock_process
        viewer_module._viewer_ready = True
        viewer_module._pty_master_fd = 10

        result = send_to_viewer("sessions")

        assert result is True
        mock_write.assert_called_once()
        call_args = mock_write.call_args
        assert call_args[0][0] == 10  # fd
        assert b"sessions\n" == call_args[0][1]


class TestSliverViewerEchoFunctions:
    """Tests for echo_* display functions."""

    @patch("sploitgpt.sliver.viewer.send_to_viewer")
    @patch("sploitgpt.sliver.viewer.is_viewer_ready", return_value=True)
    def test_echo_sessions_displays_sessions(self, mock_ready, mock_send):
        """Test echo_sessions displays session list."""
        from sploitgpt.sliver.viewer import echo_sessions

        mock_send.return_value = True

        # Create mock sessions
        mock_session = MagicMock()
        mock_session.id = "sess123456789"
        mock_session.name = "TEST_SESSION"
        mock_session.hostname = "target-host"

        echo_sessions([mock_session], None)

        assert mock_send.called
        # Check sessions header was sent
        calls = [str(c) for c in mock_send.call_args_list]
        call_str = " ".join(calls)
        assert "SESSIONS" in call_str

    @patch("sploitgpt.sliver.viewer.send_to_viewer")
    @patch("sploitgpt.sliver.viewer.is_viewer_ready", return_value=True)
    def test_echo_jobs_displays_jobs(self, mock_ready, mock_send):
        """Test echo_jobs displays job list."""
        from sploitgpt.sliver.viewer import echo_jobs

        mock_send.return_value = True

        mock_job = MagicMock()
        mock_job.id = 1
        mock_job.name = "mtls"
        mock_job.port = 8888
        mock_job.protocol = "tcp"

        echo_jobs([mock_job])

        assert mock_send.called
        calls = [str(c) for c in mock_send.call_args_list]
        call_str = " ".join(calls)
        assert "JOBS" in call_str

    @patch("sploitgpt.sliver.viewer.send_to_viewer")
    @patch("sploitgpt.sliver.viewer.is_viewer_ready", return_value=True)
    def test_echo_execute_displays_command(self, mock_ready, mock_send):
        """Test echo_execute displays command execution."""
        from sploitgpt.sliver.viewer import echo_execute

        mock_send.return_value = True

        echo_execute("sess12345678", "whoami", [])

        assert mock_send.called
        calls = [str(c) for c in mock_send.call_args_list]
        call_str = " ".join(calls)
        assert "EXECUTE" in call_str
        assert "whoami" in call_str

    @patch("sploitgpt.sliver.viewer.send_to_viewer")
    @patch("sploitgpt.sliver.viewer.is_viewer_ready", return_value=True)
    def test_echo_output_displays_output(self, mock_ready, mock_send):
        """Test echo_output displays command output."""
        from sploitgpt.sliver.viewer import echo_output

        mock_send.return_value = True

        echo_output("Line 1\nLine 2\nLine 3")

        assert mock_send.called
        # Should have header + 3 lines
        assert mock_send.call_count >= 4

    @patch("sploitgpt.sliver.viewer.send_to_viewer")
    @patch("sploitgpt.sliver.viewer.is_viewer_ready", return_value=True)
    def test_echo_output_truncates_long_output(self, mock_ready, mock_send):
        """Test echo_output truncates at max_lines."""
        from sploitgpt.sliver.viewer import echo_output

        mock_send.return_value = True

        # Generate 30 lines
        output = "\n".join([f"Line {i}" for i in range(30)])
        echo_output(output, max_lines=5)

        # Should have: 1 header + 5 lines + 1 truncation message = 7
        assert mock_send.call_count <= 8

    @patch("sploitgpt.sliver.viewer.is_viewer_ready", return_value=False)
    def test_echo_output_skips_when_not_ready(self, mock_ready):
        """Test echo_output does nothing when viewer not ready."""
        from sploitgpt.sliver.viewer import echo_output

        # Should not raise, just skip
        echo_output("Some output")

    @patch("sploitgpt.sliver.viewer.send_to_viewer")
    @patch("sploitgpt.sliver.viewer.is_viewer_ready", return_value=True)
    def test_echo_implant_generated(self, mock_ready, mock_send):
        """Test echo_implant_generated displays generation info."""
        from sploitgpt.sliver.viewer import echo_implant_generated

        mock_send.return_value = True

        echo_implant_generated("TEST_IMPLANT", "windows", "amd64", True)

        assert mock_send.called
        calls = [str(c) for c in mock_send.call_args_list]
        call_str = " ".join(calls)
        assert "IMPLANT" in call_str
        assert "BEACON" in call_str

    @patch("sploitgpt.sliver.viewer.send_to_viewer")
    @patch("sploitgpt.sliver.viewer.is_viewer_ready", return_value=True)
    def test_echo_listener_started(self, mock_ready, mock_send):
        """Test echo_listener_started displays listener info."""
        from sploitgpt.sliver.viewer import echo_listener_started

        mock_send.return_value = True

        echo_listener_started(1, "MTLS", "0.0.0.0", 8888)

        assert mock_send.called
        calls = [str(c) for c in mock_send.call_args_list]
        call_str = " ".join(calls)
        assert "LISTENER" in call_str
        assert "8888" in call_str

    @patch("sploitgpt.sliver.viewer.send_to_viewer")
    @patch("sploitgpt.sliver.viewer.is_viewer_ready", return_value=True)
    def test_echo_new_session(self, mock_ready, mock_send):
        """Test echo_new_session displays new session callback."""
        from sploitgpt.sliver.viewer import echo_new_session

        mock_send.return_value = True

        echo_new_session("sess123456789abc", "SWEET_LEMUR", "target", "admin", "linux")

        assert mock_send.called
        calls = [str(c) for c in mock_send.call_args_list]
        call_str = " ".join(calls)
        assert "NEW SESSION" in call_str


# =============================================================================
# Sliver Tools Tests
# =============================================================================


class TestSliverToolsRegistration:
    """Tests that Sliver tools are properly registered."""

    def test_sliver_tools_registered(self):
        """Test that all Sliver tools are registered."""
        from sploitgpt.tools import TOOLS

        sliver_tools = [t for t in TOOLS if t.startswith("sliver_")]

        expected_tools = [
            "sliver_sessions",
            "sliver_use",
            "sliver_execute",
            "sliver_kill",
            "sliver_listeners",
            "sliver_start_listener",
            "sliver_stop_listener",
            "sliver_generate",
            "sliver_profiles",
            "sliver_version",
        ]

        for tool in expected_tools:
            assert tool in sliver_tools, f"Expected tool {tool} not found"

    def test_sliver_tools_count(self):
        """Test correct number of Sliver tools registered."""
        from sploitgpt.tools import TOOLS

        sliver_tools = [t for t in TOOLS if t.startswith("sliver_")]
        assert len(sliver_tools) == 10


class TestSliverToolsValidation:
    """Tests for Sliver tool input validation."""

    @pytest.mark.asyncio
    async def test_sliver_use_requires_target_id(self):
        """Test sliver_use validates target_id."""
        from sploitgpt.tools.sliver import sliver_use

        result = await sliver_use("")
        assert "Error" in result
        assert "provide" in result.lower()

    @pytest.mark.asyncio
    async def test_sliver_execute_requires_target_id(self):
        """Test sliver_execute validates target_id."""
        from sploitgpt.tools.sliver import sliver_execute

        result = await sliver_execute("", "whoami")
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_sliver_execute_requires_command(self):
        """Test sliver_execute validates command."""
        from sploitgpt.tools.sliver import sliver_execute

        result = await sliver_execute("session123", "")
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_sliver_kill_requires_target_id(self):
        """Test sliver_kill validates target_id."""
        from sploitgpt.tools.sliver import sliver_kill

        result = await sliver_kill("")
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_sliver_start_listener_validates_protocol(self):
        """Test sliver_start_listener validates protocol."""
        from sploitgpt.tools.sliver import sliver_start_listener

        result = await sliver_start_listener("invalid_protocol")
        assert "Error" in result
        assert "mtls" in result.lower() or "protocol" in result.lower()

    @pytest.mark.asyncio
    async def test_sliver_start_listener_dns_requires_domain(self):
        """Test DNS listener requires domain."""
        from sploitgpt.tools.sliver import sliver_start_listener

        # Mock connection to avoid actual connection attempt
        with patch(
            "sploitgpt.tools.sliver._connect_sliver_with_retry",
            return_value=True,
        ):
            with patch("sploitgpt.tools.sliver._get_sliver_client") as mock_client:
                mock_client.return_value = MagicMock(is_connected=True)
                result = await sliver_start_listener("dns", domain="")
                assert "Error" in result
                assert "domain" in result.lower()

    @pytest.mark.asyncio
    async def test_sliver_generate_validates_os(self):
        """Test sliver_generate validates OS."""
        from sploitgpt.tools.sliver import sliver_generate

        result = await sliver_generate(os="invalid_os", c2_url="mtls://10.0.0.1:8888")
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_sliver_generate_validates_arch(self):
        """Test sliver_generate validates architecture."""
        from sploitgpt.tools.sliver import sliver_generate

        result = await sliver_generate(
            os="linux", arch="invalid_arch", c2_url="mtls://10.0.0.1:8888"
        )
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_sliver_generate_requires_c2_url(self):
        """Test sliver_generate requires C2 URL."""
        from sploitgpt.tools.sliver import sliver_generate

        result = await sliver_generate(os="linux", arch="amd64", c2_url="")
        assert "Error" in result
        assert "c2_url" in result.lower()


class TestSliverToolsConnectionHandling:
    """Tests for Sliver tools connection error handling."""

    @pytest.mark.asyncio
    async def test_sliver_sessions_handles_connection_failure(self):
        """Test sliver_sessions handles connection failure gracefully."""
        from sploitgpt.tools.sliver import sliver_sessions

        with patch(
            "sploitgpt.tools.sliver._connect_sliver_with_retry",
            return_value=False,
        ):
            with patch("sploitgpt.tools.sliver._get_sliver_client") as mock_client:
                mock_client.return_value = MagicMock(is_connected=False)
                result = await sliver_sessions()
                assert "Error" in result or "could not connect" in result.lower()

    @pytest.mark.asyncio
    async def test_sliver_version_handles_connection_failure(self):
        """Test sliver_version handles connection failure gracefully."""
        from sploitgpt.tools.sliver import sliver_version

        with patch(
            "sploitgpt.tools.sliver._connect_sliver_with_retry",
            return_value=False,
        ):
            with patch("sploitgpt.tools.sliver._get_sliver_client") as mock_client:
                mock_client.return_value = MagicMock(is_connected=False)
                result = await sliver_version()
                assert "Error" in result or "could not connect" in result.lower()


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_get_sliver_client_returns_client(self):
        """Test get_sliver_client returns SliverRPC instance."""
        from sploitgpt.sliver import get_sliver_client

        client = get_sliver_client()
        assert client is not None
        assert hasattr(client, "connect")
        assert hasattr(client, "list_sessions")

    def test_get_sliver_client_with_config_path(self, tmp_path):
        """Test get_sliver_client with custom config path."""
        from sploitgpt.sliver import get_sliver_client

        config_file = tmp_path / "custom.cfg"
        config_file.touch()

        client = get_sliver_client(str(config_file))
        assert client.config_path == config_file

    @pytest.mark.asyncio
    async def test_list_sliver_sessions_not_connected(self):
        """Test list_sliver_sessions handles not connected."""
        from sploitgpt.sliver import list_sliver_sessions

        # Without mocking connection, should return some result (not crash)
        result = await list_sliver_sessions()
        # Could be connection error, empty sessions, or other graceful response
        assert isinstance(result, str) and len(result) > 0
