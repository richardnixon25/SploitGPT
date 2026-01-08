# SploitGPT Sliver C2 Integration - Implementation Guide

## Overview

This document outlines the complete implementation plan for integrating Sliver C2 into SploitGPT, including a unified web dashboard for visualizing both Metasploit and Sliver operations.

**Goal:** Create an AI-powered penetration testing framework that uses:
- **Metasploit** for scanning, exploitation, and initial access
- **Sliver** for post-exploitation, persistence, and long-term C2
- **Unified Web Dashboard** for visualization and monitoring
- **TUI** for primary operator interaction with the LLM

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Operator Interface                        │
│  ┌─────────────────────────┐  ┌───────────────────────────────┐ │
│  │    TUI (Primary)        │  │    Web Dashboard (Monitor)    │ │
│  │  - LLM conversation     │  │  - Session visualization      │ │
│  │  - Intent → Confirm     │  │  - Task history               │ │
│  │  - Real-time feedback   │  │  - Network graph              │ │
│  └───────────┬─────────────┘  └───────────────┬───────────────┘ │
└──────────────┼────────────────────────────────┼─────────────────┘
               │                                │
               └────────────┬───────────────────┘
                            │
               ┌────────────▼────────────┐
               │    SploitGPT Core       │
               │  ┌──────────────────┐   │
               │  │   LLM (Ollama)   │   │
               │  │  sploitgpt-7b    │   │
               │  └────────┬─────────┘   │
               │           │             │
               │  ┌────────▼─────────┐   │
               │  │  Tool Router     │   │
               │  │  (MSF + Sliver)  │   │
               │  └────────┬─────────┘   │
               └───────────┼─────────────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
   ┌────────────┐   ┌────────────┐   ┌────────────┐
   │ Metasploit │   │   Sliver   │   │   Kali     │
   │    RPC     │   │   gRPC     │   │   Tools    │
   │ (port 55553)│  │(port 31337)│   │            │
   └────────────┘   └────────────┘   └────────────┘
        │                │
        ▼                ▼
   ┌─────────┐      ┌─────────┐
   │ MSF     │      │ Sliver  │
   │ Viewer  │      │ Viewer  │
   │ (PTY)   │      │ (PTY)   │
   └─────────┘      └─────────┘
```

---

## Implementation Phases

### Phase 1: Sliver Infrastructure (Week 1)

#### 1.1 Add Sliver Container
**File:** `compose.yaml`

Add Sliver as a separate container:
```yaml
services:
  sliver:
    build:
      context: ./docker/sliver
      dockerfile: Dockerfile
    container_name: sploitgpt-sliver
    volumes:
      - sliver-data:/root/.sliver
      - ./configs/sliver:/configs
    ports:
      - "31337:31337"    # Operator gRPC API
      - "8888:8888"      # mTLS implant listener
      - "80:80"          # HTTP C2
      - "443:443"        # HTTPS C2
    restart: unless-stopped

volumes:
  sliver-data:
```

#### 1.2 Sliver Dockerfile
**File:** `docker/sliver/Dockerfile`

```dockerfile
FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl ca-certificates netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

ARG SLIVER_VERSION=v1.5.42
RUN curl -L -o /usr/local/bin/sliver-server \
    https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-server_linux && \
    chmod +x /usr/local/bin/sliver-server

WORKDIR /root/.sliver
EXPOSE 31337 8888 80 443

ENTRYPOINT ["/usr/local/bin/sliver-server", "daemon"]
```

#### 1.3 Sliver Client Module
**Directory:** `sploitgpt/sliver/`

```
sploitgpt/sliver/
├── __init__.py          # SliverClient wrapper class
├── client.py            # gRPC client implementation
├── viewer.py            # Real-time viewer (like MSF viewer)
├── operations.py        # High-level operations
└── models.py            # Data models for sessions/beacons
```

#### 1.4 Core Client Implementation
**File:** `sploitgpt/sliver/__init__.py`

Key features:
- Async connection to Sliver server via sliver-py
- Session/beacon management
- Command execution with output capture
- Implant generation
- File upload/download
- Auto-call `echo_rpc_call()` for viewer integration

#### 1.5 Sliver Viewer
**File:** `sploitgpt/sliver/viewer.py`

Mirror MSF viewer functionality:
- Open PTY-based terminal showing Sliver console
- Intro banner explaining what user sees
- Color-coded operations (sessions=green, beacons=cyan, commands=white)
- Visual separators between operation types
- Echo all gRPC calls as equivalent console commands

---

### Phase 2: Web Dashboard Foundation (Week 2)

#### 2.1 Copy BYOB Web Structure
Fork the BYOB web-gui structure as starting point:
```
sploitgpt/web/
├── __init__.py          # Flask/FastAPI app factory
├── api/
│   ├── __init__.py
│   ├── sessions.py      # Unified sessions endpoint (MSF + Sliver)
│   ├── tasks.py         # Command history
│   ├── loot.py          # Exfiltrated files
│   └── llm.py           # LLM activity feed
├── templates/
│   ├── layout.html
│   ├── dashboard.html
│   ├── sessions.html
│   ├── shell.html
│   └── network.html
├── static/
│   ├── css/
│   ├── js/
│   └── images/
└── models.py            # Database models
```

#### 2.2 Backend API
**Framework:** FastAPI (async, WebSocket support, Python)

Endpoints:
```
GET  /api/sessions        # All sessions (MSF + Sliver combined)
GET  /api/sessions/{id}   # Single session details
POST /api/sessions/{id}/cmd  # Execute command
GET  /api/beacons         # Sliver beacons
GET  /api/tasks           # Command history
GET  /api/loot            # Exfiltrated files
WS   /api/ws/events       # Real-time event stream
GET  /api/llm/activity    # What the LLM is doing
```

#### 2.3 Unified Session Model
```python
class UnifiedSession:
    id: str
    source: Literal["msf", "sliver"]
    type: Literal["session", "beacon", "meterpreter", "shell"]
    target_host: str
    target_user: str
    os: str
    arch: str
    status: Literal["active", "dormant", "dead"]
    last_checkin: datetime
    created_at: datetime
```

---

### Phase 3: Dashboard Features (Week 3)

#### 3.1 Session List View
- Combined table of MSF sessions + Sliver sessions/beacons
- Color-coded by source (MSF=red, Sliver=blue)
- Status indicators (active/dormant/dead)
- Quick actions (shell, kill, info)

#### 3.2 Interactive Shell
- Reuse jQuery Terminal from BYOB
- WebSocket connection for real-time I/O
- Support both MSF and Sliver sessions
- Command history

#### 3.3 Task History
- All commands executed across all sessions
- Timestamp, session, command, result
- Filter by session, time range, command type
- Export to file

#### 3.4 Network Graph
- D3.js or vis.js visualization
- Nodes = compromised hosts
- Edges = pivot relationships
- Click node to see sessions on that host

#### 3.5 LLM Activity Feed
- Real-time stream of LLM decisions
- What it's analyzing
- What actions it's proposing
- Approval status
- Execution results

---

### Phase 4: LLM Integration (Week 4)

#### 4.1 Sliver Tools for LLM
Add to LLM's available tools:
```python
SLIVER_TOOLS = [
    "sliver_list_sessions",
    "sliver_list_beacons",
    "sliver_interact",
    "sliver_execute",
    "sliver_upload",
    "sliver_download",
    "sliver_screenshot",
    "sliver_ps",
    "sliver_netstat",
    "sliver_pivot",
    "sliver_generate_implant",
]
```

#### 4.2 Tool Router
Enhance existing tool router to handle both MSF and Sliver:
```python
async def route_tool(tool_name: str, params: dict):
    if tool_name.startswith("msf_"):
        return await msf_handler(tool_name, params)
    elif tool_name.startswith("sliver_"):
        return await sliver_handler(tool_name, params)
    elif tool_name.startswith("kali_"):
        return await kali_handler(tool_name, params)
```

#### 4.3 Context Injection
Inject active sessions into LLM context:
```python
def build_context():
    msf_sessions = msf_client.sessions()
    sliver_sessions = sliver_client.sessions()
    sliver_beacons = sliver_client.beacons()
    
    return f"""
    Active MSF Sessions: {format_sessions(msf_sessions)}
    Active Sliver Sessions: {format_sessions(sliver_sessions)}
    Active Sliver Beacons: {format_beacons(sliver_beacons)}
    """
```

---

## Key Technical Details

### sliver-py Usage

```python
from sliver import SliverClientConfig, SliverClient

class SploitGPTSliverClient:
    def __init__(self, config_path: str):
        self.config = SliverClientConfig.parse_config_file(config_path)
        self.client = SliverClient(self.config)
        self._connected = False
    
    async def connect(self):
        await self.client.connect()
        self._connected = True
    
    async def list_sessions(self):
        return await self.client.sessions()
    
    async def list_beacons(self):
        return await self.client.beacons()
    
    async def interact_session(self, session_id: str):
        return await self.client.interact_session(session_id)
    
    async def execute(self, session_id: str, cmd: str, args: list):
        interact = await self.interact_session(session_id)
        return await interact.execute(cmd, args, output=True)
```

### Viewer Integration

Every Sliver operation should call `echo_rpc_call()` to show in viewer:
```python
async def execute(self, session_id: str, cmd: str, args: list):
    # Echo to viewer
    from sploitgpt.sliver.viewer import echo_rpc_call
    echo_rpc_call("execute", [session_id, cmd, args])
    
    # Execute
    interact = await self.interact_session(session_id)
    result = await interact.execute(cmd, args, output=True)
    
    # Echo result
    from sploitgpt.sliver.viewer import echo_output
    echo_output(result.Stdout)
    
    return result
```

### WebSocket Events
```python
# Backend broadcasts events
async def broadcast_event(event_type: str, data: dict):
    for ws in active_websockets:
        await ws.send_json({
            "type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        })

# Event types
# - session_new, session_dead
# - beacon_new, beacon_checkin
# - task_created, task_completed
# - llm_thinking, llm_proposing, llm_executing
```

---

## File Structure Summary

```
SploitGPT/
├── compose.yaml                    # Add Sliver service
├── docker/
│   └── sliver/
│       └── Dockerfile              # Sliver container
├── configs/
│   └── sliver/
│       └── operator.cfg            # Generated operator config
├── sploitgpt/
│   ├── sliver/
│   │   ├── __init__.py             # SliverClient class
│   │   ├── client.py               # gRPC implementation
│   │   ├── viewer.py               # Real-time viewer
│   │   ├── operations.py           # High-level ops
│   │   └── models.py               # Data models
│   ├── web/
│   │   ├── __init__.py             # FastAPI app
│   │   ├── api/
│   │   │   ├── sessions.py
│   │   │   ├── tasks.py
│   │   │   ├── loot.py
│   │   │   └── llm.py
│   │   ├── templates/              # Jinja2 templates
│   │   ├── static/                 # CSS/JS/images
│   │   └── models.py
│   └── core/
│       └── tool_router.py          # Route tools to MSF/Sliver
└── docs/
    └── SLIVER_INTEGRATION.md       # This document
```

---

## Dependencies to Add

**Python packages:**
```
sliver-py>=0.0.21
fastapi>=0.109.0
uvicorn>=0.27.0
websockets>=12.0
python-multipart>=0.0.6
jinja2>=3.1.0
```

**Frontend (from BYOB):**
- jQuery Terminal
- DataTables
- Bootstrap
- D3.js or vis.js (for network graph)

---

## Testing Checklist

### Phase 1
- [ ] Sliver container builds and starts
- [ ] Can generate operator config
- [ ] sliver-py connects successfully
- [ ] List sessions/beacons works
- [ ] Execute command works
- [ ] Sliver viewer opens and displays operations

### Phase 2
- [ ] Web dashboard loads
- [ ] Session list shows MSF + Sliver combined
- [ ] API endpoints return correct data
- [ ] WebSocket events stream correctly

### Phase 3
- [ ] Interactive shell works (both MSF and Sliver)
- [ ] Task history populates
- [ ] Network graph renders
- [ ] LLM activity feed updates in real-time

### Phase 4
- [ ] LLM can use Sliver tools
- [ ] Approval flow works for Sliver commands
- [ ] LLM context includes active sessions
- [ ] End-to-end: User intent → LLM suggests → Confirm → Execute on Sliver

---

## Commands Reference

```bash
# Build and start Sliver
cd /home/cheese/SploitGPT
podman compose up -d sliver

# Generate operator config
podman exec -it sploitgpt-sliver sliver-server operator \
    --name sploitgpt --lhost 127.0.0.1 --save /configs/sploitgpt.cfg

# Test sliver-py connection
python -c "
import asyncio
from sliver import SliverClientConfig, SliverClient
async def test():
    config = SliverClientConfig.parse_config_file('configs/sliver/sploitgpt.cfg')
    client = SliverClient(config)
    await client.connect()
    print('Connected!')
    sessions = await client.sessions()
    print(f'Sessions: {len(sessions)}')
asyncio.run(test())
"

# Run web dashboard
cd sploitgpt/web && uvicorn __init__:app --reload --port 8080

# Run all tests
python -m pytest tests/ -v
```

---

## Notes

1. **Sliver vs MSF Use Cases:**
   - MSF: Scanning, initial exploitation, known CVEs
   - Sliver: Post-exploitation, persistence, long-term access

2. **Beacon vs Session:**
   - Sessions are persistent connections (like MSF meterpreter)
   - Beacons are async check-ins (stealthier, commands queue)

3. **Security:**
   - Operator configs contain private keys - keep secure
   - Web dashboard should be localhost-only or properly authenticated
   - Never expose 31337 (Sliver API) to internet without VPN

4. **Performance:**
   - Beacon commands return Futures - must await result
   - Implant generation takes 30-60+ seconds (Go compilation)
   - Use connection pooling for web dashboard
