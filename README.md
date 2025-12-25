# SploitGPT

```text
 ███████╗██████╗ ██╗      ██████╗ ██╗████████╗ ██████╗ ██████╗ ████████╗
 ██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝ ██╔══██╗╚══██╔══╝
 ███████╗██████╔╝██║     ██║   ██║██║   ██║   ██║  ███╗██████╔╝   ██║   
 ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ██║   ██║██╔═══╝    ██║   
 ███████║██║     ███████╗╚██████╔╝██║   ██║   ╚██████╔╝██║        ██║   
 ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝        ╚═╝   
                                                                         
            [ Autonomous AI Penetration Testing Framework ]
```

> **⚠️ AUTHORIZED USE ONLY** - This tool is for authorized penetration testing and security research only. Unauthorized access to computer systems is illegal.

## What is SploitGPT?

SploitGPT is an AI-powered penetration testing framework that:

- 🧠 **Preloaded security brain** - Uses a local model plus RAG over Kali tool docs, MITRE ATT&CK, and exploit references
- 🔄 **Context-aware** - Uses your session state/loot to stay on-target (no auto-training loops)
- 🎯 **Asks, doesn't guess** - Clarifying questions instead of wrong assumptions
- 🔓 **Runs 100% locally** - Private, secure, no API costs after install
- ⚡ **Executes autonomously** - Actually runs commands, not just suggestions

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/sploitgpt.git
cd sploitgpt

# Install (sets up Docker/Ollama/model, no fine-tuning required)
./install.sh

# Run
./sploitgpt

# If you run the Python CLI outside Docker:
pip install -r requirements.txt
python3 -m sploitgpt.cli --task "say hi" --cli
```

## Requirements

- **Docker**
- **NVIDIA GPU** with 8GB+ VRAM (for local LLM)
- **Ollama** (auto-installed)
- Linux (tested on Kali, Ubuntu, Debian)

## Features

### 🎯 Intelligent Attack Planning

SploitGPT uses MITRE ATT&CK techniques to plan attacks. When multiple paths exist, it asks you:

```text
sploitgpt > compromise 10.0.0.1

🔍 Scanning target...

PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
445/tcp open  smb

Multiple attack paths available:
[1] 🌐 Web Application (T1190) - Test for vulns, SQLi, RCE
[2] 📁 SMB Shares (T1021.002) - Enumerate shares, null session
[3] 🔑 Credential Attack (T1110) - Brute force SSH
[4] 🎯 Full Assessment - Try all paths

>
```

### 🔧 Metasploit Integration

Uses Metasploit as the exploitation backend - no reinventing the wheel:

```text
sploitgpt > use exploit for CVE-2021-44228

Using: exploit/multi/http/log4shell_header_injection
Setting RHOSTS=10.0.0.1
Launching exploit...

[*] Meterpreter session 1 opened
```

### 💻 Hybrid Terminal

Direct shell access + AI commands in one interface:

```bash
# Direct shell command
sploitgpt > nmap -sV 10.0.0.1

# AI-assisted command (prefix with /)
sploitgpt > /enumerate this target

# Or just ask
sploitgpt > what services are running?
```

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                         SploitGPT                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   Ollama    │  │   Hybrid    │  │      Metasploit         │ │
│  │   (Local    │◄►│   Terminal  │◄►│      RPC Backend        │ │
│  │    LLM)     │  │   (TUI)     │  │                         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
│         │                │                      │              │
│         ▼                ▼                      ▼              │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    Kali Linux Container                     ││
│  │  nmap • gobuster • sqlmap • hydra • nuclei • burp • ...    ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Network Configuration

SploitGPT supports flexible network configurations for different pentesting scenarios.

- Metasploit RPC is local-only (forced to loopback) while Metasploit itself can target LAN/WAN hosts normally.

### Network Modes

#### 1. Dual-Bridge (Default)

SploitGPT runs with two Docker networks:

- **sploitnet_internal (internal)**: Ollama only (no WAN)
- **sploitnet_wan**: SploitGPT container with outbound WAN access for tools

Ollama is exposed to the host on `127.0.0.1:11434` for the TUI but is not
reachable from the LAN.

```yaml
# docker-compose.yml (default)
networks:
  sploitnet_internal:
    internal: true
  sploitnet_wan:
    driver: bridge
```

#### 2. Host Networking (Advanced)

If you need raw host networking (VPN/WiFi adapter access), switch the SploitGPT
service to `network_mode: host` and run Ollama on the host (or expose it explicitly),
then set `SPLOITGPT_OLLAMA_HOST` to the host endpoint.

### Listener Ports (On Demand)

Inbound listeners (reverse shells, payload servers) are closed unless a tool binds.
Enable port publishing only when you need it:

```bash
docker compose --profile listeners up -d listener-proxy
```

By default, the published range is `40000-40100` (override via `SPLOITGPT_LISTENER_PORTS`).
Use ports in that range for `LPORT`.

### Environment Variables

Configure via `.env` file or environment:

```bash
# Generate auto-detected config
./scripts/network_config.sh

# Or set manually:
SPLOITGPT_OLLAMA_HOST=http://ollama:11434       # Ollama endpoint
SPLOITGPT_MODEL=sploitgpt-local-q3:latest      # Custom SploitGPT model (Ollama tag)
SPLOITGPT_LLM_MODEL=sploitgpt-local-q3:latest  # Normalized model name used by the app
SPLOITGPT_MSF_HOST=127.0.0.1                    # MSF RPC bind address
SPLOITGPT_MSF_PORT=55553                        # MSF RPC port
SPLOITGPT_MSF_PASSWORD=msf                      # MSF RPC password
SPLOITGPT_MSF_VERIFY_SSL=true                   # Verify MSF RPC SSL certs (if SSL is enabled)
SPLOITGPT_LPORT=40000                           # Default listener port
SPLOITGPT_LISTENER_PORTS=40000-40100            # Published listener range
# Optional: enable the Shodan tool
SHODAN_API_KEY=your_shodan_api_key
```

### Host Ollama (Optional)

If you run Ollama on the host instead of Docker, set the host endpoint:

```bash
# Force specific Ollama endpoint
export SPLOITGPT_OLLAMA_HOST=http://127.0.0.1:11434
docker-compose up -d
```

## Security Configuration

SploitGPT is designed to run securely with the following setup:

### Default Isolation

- **Ollama**: internal Docker network + host-only bind `127.0.0.1:11434` (not exposed to LAN)
- **SploitGPT**: WAN access via `sploitnet_wan`
- **LiteLLM proxy**: removed in favor of direct Ollama OpenAI-compatible API

### Host Ollama Firewall (Optional)

```bash
# Automated setup (configures UFW/iptables + Ollama binding)
sudo ./scripts/firewall_setup.sh

# Or manually:
# 1. Configure Ollama to bind to Docker bridge
sudo mkdir -p /etc/systemd/system/ollama.service.d
echo '[Service]
Environment="OLLAMA_HOST=172.17.0.1"' | sudo tee /etc/systemd/system/ollama.service.d/override.conf
sudo systemctl daemon-reload && sudo systemctl restart ollama

# 2. Add firewall rules
sudo ufw allow from 172.17.0.0/16 to any port 11434 proto tcp
sudo ufw deny 11434/tcp
```

### Scenario: WiFi Attack / LAN Pentest

For engagements where you join a target network:

```bash
# 1. Connect to target WiFi
nmcli dev wifi connect "TargetNetwork" password "password123"

# 2. Start container with host networking
docker-compose up -d  # network_mode: host in compose file

# 3. Container now has direct LAN access
docker exec -it sploitgpt sploitgpt
sploitgpt > scan 192.168.1.0/24
```

### Scenario: VPN Tunnel

For anonymous pentesting through VPN:

```bash
# 1. Connect VPN on host
mullvad connect

# 2. Verify VPN
curl https://am.i.mullvad.net/connected  # Should show connected

# 3. Start container (inherits VPN via host networking)
docker-compose up -d
```

### Verify Security

```bash
# Ollama should NOT be accessible from localhost or network
curl http://localhost:11434/api/tags        # Should fail
curl http://YOUR_LAN_IP:11434/api/tags      # Should fail

# But accessible from container
docker exec sploitgpt curl http://ollama:11434/api/tags  # Should work
```

## Knowledge Sources (No Auto-Training)

- Local model packaged for security tasks (Kali tool docs, MITRE ATT&CK, exploit references)
- RAG over bundled docs and your stored loot/sessions to stay context-aware
- No automatic fine-tuning loops; the bundled model + RAG is the intended path

## License

MIT License - See [LICENSE](LICENSE)

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. Users are responsible for complying with all applicable laws. The developers assume no liability for misuse.

---
