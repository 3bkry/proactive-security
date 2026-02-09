import asyncio
import json
import os
from typing import Dict, Any, Optional

from agent.sentinel.config.defaults import DEFAULT_SOCKET_PATH

class IPCClient:
    def __init__(self, socket_path: str = None):
        self.socket_path = socket_path or os.environ.get("SENTINEL_SOCKET") or str(DEFAULT_SOCKET_PATH)

    async def call(self, method: str, params: Dict[str, Any] = None) -> Any:
        if not os.path.exists(self.socket_path):
            raise ConnectionError(f"Agent socket not found at {self.socket_path}. Is the agent running?")

        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        
        try:
            request = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params or {},
                "id": 1
            }
            
            writer.write(json.dumps(request).encode() + b"\n")
            await writer.drain()
            
            data = await reader.readuntil(b"\n")
            response = json.loads(data.decode())
            
            if "error" in response:
                raise RuntimeError(response["error"]["message"])
                
            return response.get("result")
            
        finally:
            writer.close()
            await writer.wait_closed()

def run_command(method: str, params: Dict[str, Any] = None) -> Any:
    """Helper to run sync command from CLI."""
    client = IPCClient()
    return asyncio.run(client.call(method, params))
