import asyncio
import json
import os
from typing import Callable, Dict, Any, Awaitable

from .utils.logging import get_logger

logger = get_logger("ipc_server")

class IPCServer:
    def __init__(self, socket_path: str, handlers: Dict[str, Callable[[Any], Awaitable[Any]]]):
        self.socket_path = socket_path
        self.handlers = handlers
        self.server = None

    async def start(self):
        # Remove existing socket
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.socket_path), exist_ok=True)

        self.server = await asyncio.start_unix_server(
            self.handle_client, self.socket_path
        )
        logger.info(f"IPC Server listening on {self.socket_path}")

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
            logger.info("IPC Server stopped")

    async def handle_client(self, reader, writer):
        try:
            while True:
                data = await reader.readuntil(b"\n")
                if not data:
                    break
                
                request = json.loads(data.decode().strip())
                response = await self.process_request(request)
                
                writer.write(json.dumps(response).encode() + b"\n")
                await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            logger.error(f"IPC Client Error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def process_request(self, request: Dict) -> Dict:
        method = request.get("method")
        params = request.get("params", {})
        msg_id = request.get("id")
        
        if method not in self.handlers:
            return {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": msg_id}
        
        try:
            result = await self.handlers[method](params)
            return {"jsonrpc": "2.0", "result": result, "id": msg_id}
        except Exception as e:
            logger.error(f"Error processing {method}: {e}")
            return {"jsonrpc": "2.0", "error": {"code": -32000, "message": str(e)}, "id": msg_id}
