"""
Metasploit RPC Integration

Connects to msfrpcd for exploit search and execution.
Uses MSF as the backend instead of reinventing exploit management.
"""

import asyncio
import json
import msgpack
import ssl
from typing import Optional, Any
from dataclasses import dataclass

import httpx


@dataclass
class MSFModule:
    """Represents a Metasploit module."""
    type: str  # exploit, auxiliary, post, payload
    name: str  # full module path
    rank: str  # excellent, great, good, normal, average, low, manual
    description: str
    references: list[str]
    
    @property
    def short_name(self) -> str:
        """Get the short module name."""
        return self.name.split("/")[-1]


@dataclass
class MSFSession:
    """Represents an active MSF session."""
    id: int
    type: str  # shell, meterpreter
    tunnel_local: str
    tunnel_peer: str
    via_exploit: str
    via_payload: str
    info: str
    workspace: str


class MetasploitRPC:
    """
    Metasploit RPC Client.
    
    Connects to msfrpcd for module search, execution, and session management.
    """
    
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        username: str = "msf",
        password: str = "msf",
        ssl: bool = True,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = ssl
        self.token: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None
    
    @property
    def base_url(self) -> str:
        """Get the base URL for the RPC server."""
        scheme = "https" if self.use_ssl else "http"
        return f"{scheme}://{self.host}:{self.port}/api"
    
    async def connect(self) -> bool:
        """Connect and authenticate with msfrpcd."""
        try:
            # Create client with SSL verification disabled (self-signed cert)
            self._client = httpx.AsyncClient(
                verify=False,
                timeout=30.0,
            )
            
            # Authenticate
            result = await self._call("auth.login", [self.username, self.password])
            
            if result.get("result") == "success":
                self.token = result.get("token")
                return True
            
            return False
            
        except Exception as e:
            print(f"MSF connection failed: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from msfrpcd."""
        if self.token:
            try:
                await self._call("auth.logout", [self.token])
            except:
                pass
        
        if self._client:
            await self._client.aclose()
            self._client = None
        
        self.token = None
    
    async def _call(self, method: str, params: list = None) -> dict:
        """Make an RPC call to msfrpcd."""
        if not self._client:
            raise RuntimeError("Not connected to MSF")
        
        params = params or []
        
        # Add token to authenticated calls
        if self.token and method != "auth.login":
            params = [self.token] + params
        
        # Pack request
        request_data = msgpack.packb([method] + params)
        
        response = await self._client.post(
            self.base_url,
            content=request_data,
            headers={"Content-Type": "binary/message-pack"},
        )
        
        response.raise_for_status()
        
        # Unpack response
        return msgpack.unpackb(response.content, raw=False)
    
    # =========================================================================
    # Module Operations
    # =========================================================================
    
    async def search_modules(
        self,
        query: str,
        module_type: Optional[str] = None,
    ) -> list[MSFModule]:
        """
        Search for MSF modules.
        
        Args:
            query: Search query (e.g., "vsftpd", "apache struts")
            module_type: Filter by type (exploit, auxiliary, post)
            
        Returns:
            List of matching modules
        """
        # Use module.search
        search_params = f"name:{query}"
        if module_type:
            search_params += f" type:{module_type}"
        
        result = await self._call("module.search", [search_params])
        
        modules = []
        for item in result:
            modules.append(MSFModule(
                type=item.get("type", ""),
                name=item.get("fullname", ""),
                rank=item.get("rank", "normal"),
                description=item.get("name", ""),
                references=item.get("references", []),
            ))
        
        # Sort by rank
        rank_order = {
            "excellent": 0,
            "great": 1,
            "good": 2,
            "normal": 3,
            "average": 4,
            "low": 5,
            "manual": 6,
        }
        modules.sort(key=lambda m: rank_order.get(m.rank, 99))
        
        return modules
    
    async def get_module_info(self, module_type: str, module_name: str) -> dict:
        """Get detailed info about a module."""
        return await self._call("module.info", [module_type, module_name])
    
    async def get_module_options(self, module_type: str, module_name: str) -> dict:
        """Get module options."""
        return await self._call("module.options", [module_type, module_name])
    
    # =========================================================================
    # Module Execution
    # =========================================================================
    
    async def execute_module(
        self,
        module_type: str,
        module_name: str,
        options: dict,
    ) -> dict:
        """
        Execute a module.
        
        Args:
            module_type: Module type (exploit, auxiliary, post)
            module_name: Full module name
            options: Module options (RHOSTS, RPORT, etc.)
            
        Returns:
            Execution result with job_id or session info
        """
        return await self._call(
            "module.execute",
            [module_type, module_name, options]
        )
    
    async def get_job_info(self, job_id: int) -> dict:
        """Get info about a running job."""
        jobs = await self._call("job.list", [])
        return jobs.get(str(job_id), {})
    
    async def stop_job(self, job_id: int) -> bool:
        """Stop a running job."""
        result = await self._call("job.stop", [job_id])
        return result.get("result") == "success"
    
    # =========================================================================
    # Session Management
    # =========================================================================
    
    async def list_sessions(self) -> list[MSFSession]:
        """List active sessions."""
        result = await self._call("session.list", [])
        
        sessions = []
        for sid, info in result.items():
            sessions.append(MSFSession(
                id=int(sid),
                type=info.get("type", ""),
                tunnel_local=info.get("tunnel_local", ""),
                tunnel_peer=info.get("tunnel_peer", ""),
                via_exploit=info.get("via_exploit", ""),
                via_payload=info.get("via_payload", ""),
                info=info.get("info", ""),
                workspace=info.get("workspace", ""),
            ))
        
        return sessions
    
    async def session_write(self, session_id: int, data: str) -> bool:
        """Write to a session (shell input)."""
        result = await self._call("session.shell_write", [session_id, data])
        return result.get("write_count", 0) > 0
    
    async def session_read(self, session_id: int) -> str:
        """Read from a session (shell output)."""
        result = await self._call("session.shell_read", [session_id])
        return result.get("data", "")
    
    async def session_stop(self, session_id: int) -> bool:
        """Stop/kill a session."""
        result = await self._call("session.stop", [session_id])
        return result.get("result") == "success"
    
    # =========================================================================
    # Console Operations (for interactive use)
    # =========================================================================
    
    async def console_create(self) -> int:
        """Create a new MSF console."""
        result = await self._call("console.create", [])
        return result.get("id")
    
    async def console_write(self, console_id: int, command: str) -> bool:
        """Write to a console."""
        result = await self._call("console.write", [console_id, command + "\n"])
        return result.get("wrote", 0) > 0
    
    async def console_read(self, console_id: int) -> tuple[str, bool]:
        """Read from a console. Returns (output, busy)."""
        result = await self._call("console.read", [console_id])
        return result.get("data", ""), result.get("busy", False)
    
    async def console_destroy(self, console_id: int) -> bool:
        """Destroy a console."""
        result = await self._call("console.destroy", [console_id])
        return result.get("result") == "success"


# Convenience functions for agent use
async def search_exploits(query: str, msf: Optional[MetasploitRPC] = None) -> str:
    """Search for exploits and return formatted results."""
    own_client = msf is None
    
    if own_client:
        msf = MetasploitRPC()
        if not await msf.connect():
            return "❌ Could not connect to Metasploit. Is msfrpcd running?"
    
    try:
        modules = await msf.search_modules(query, module_type="exploit")
        
        if not modules:
            return f"No exploits found for '{query}'"
        
        lines = [f"**Found {len(modules)} exploits for '{query}':**\n"]
        
        for i, mod in enumerate(modules[:10], 1):
            rank_emoji = {
                "excellent": "🟢",
                "great": "🟢", 
                "good": "🟡",
                "normal": "🟡",
                "average": "🟠",
                "low": "🔴",
                "manual": "⚪",
            }.get(mod.rank, "⚪")
            
            lines.append(f"{i}. {rank_emoji} `{mod.name}`")
            lines.append(f"   {mod.description[:80]}...")
            lines.append("")
        
        if len(modules) > 10:
            lines.append(f"_...and {len(modules) - 10} more_")
        
        return "\n".join(lines)
        
    finally:
        if own_client:
            await msf.disconnect()


async def run_exploit(
    module_name: str,
    options: dict,
    msf: Optional[MetasploitRPC] = None,
) -> str:
    """Run an exploit and return results."""
    own_client = msf is None
    
    if own_client:
        msf = MetasploitRPC()
        if not await msf.connect():
            return "❌ Could not connect to Metasploit. Is msfrpcd running?"
    
    try:
        # Execute the exploit
        result = await msf.execute_module("exploit", module_name, options)
        
        if "error" in result:
            return f"❌ Error: {result['error_message']}"
        
        job_id = result.get("job_id")
        
        if job_id:
            # Wait a bit for exploit to run
            await asyncio.sleep(3)
            
            # Check for new sessions
            sessions = await msf.list_sessions()
            new_sessions = [s for s in sessions if s.via_exploit.endswith(module_name)]
            
            if new_sessions:
                session = new_sessions[-1]
                return f"""🎯 **Exploit Successful!**

**Session {session.id}** opened
- Type: {session.type}
- Target: {session.tunnel_peer}
- Via: {session.via_exploit}

Use `session_interact({session.id})` to interact with the session."""
            
            return f"⏳ Exploit running (job {job_id}). Check `msf.list_sessions()` for shells."
        
        return f"Exploit result: {json.dumps(result, indent=2)}"
        
    finally:
        if own_client:
            await msf.disconnect()
