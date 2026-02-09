import asyncio
import signal
import sys
from pathlib import Path

from .config.loader import load_config
from .store.database import ThreatStore
from .collector.watcher import LogWatcher
from .collector.discovery import perform_discovery
from .detector.pipeline import DetectionPipeline
from .utils.logging import setup_logging, get_logger
from .ipc import IPCServer

logger = get_logger("agent")

class SentinelAgent:
    def __init__(self, config_path: str = None):
        self.config = load_config(Path(config_path) if config_path else None)
        setup_logging(self.config.agent.log_level)
        
        self.store = ThreatStore(self.config.database.path)
        self.watcher = LogWatcher([])
        self.detector = DetectionPipeline(self.config.detection)
        
        # IPC handlers
        self.ipc_handlers = {
            "status": self.handle_status,
            "threats": self.handle_threats,
        }
        self.ipc = IPCServer(self.config.agent.ipc_socket, self.ipc_handlers)
        
        self._running = False

    async def run(self):
        """Main service loop."""
        logger.info(f"Starting Sentinel Agent v0.1.0")
        logger.info(f"Database: {self.config.database.path}")
        
        # Initialize components
        await self.store.initialize()
        await self.ipc.start()
        
        # Discover logs
        if self.config.logs.discovery:
            logs = perform_discovery()
            for log_type, paths in logs.items():
                for p in paths:
                    self.watcher.add_path(p)
        
        # Add configured logs
        for source in self.config.logs.sources:
            if source.enabled:
                self.watcher.add_path(source.path)

        self._running = True
        
        # Event loop
        try:
            async for event in self.watcher.watch():
                if not self._running:
                    break
                    
                threat = await self.detector.analyze(event.source_path, event.content)
                if threat:
                    logger.warning(f"THREAT DETECTED: {threat.description} from {threat.attacker_ip}")
                    await self.store.save_threat(threat)
                    # TODO: Response Engine trigger
                    
        except asyncio.CancelledError:
            logger.info("Agent stopping...")
        finally:
            await self.shutdown()

    async def shutdown(self):
        self._running = False
        if hasattr(self, 'ipc'):
            await self.ipc.stop()
        await self.store.close()
        logger.info("Agent stopped.")

    async def handle_status(self, params):
        return {
            "status": "running",
            "uptime": "TODO",  # Implement uptime tracking
            "monitored_files": list(self.watcher.tailers.keys())
        }

    async def handle_threats(self, params):
        limit = params.get("limit", 10)
        threats = await self.store.get_threats(limit)
        return [
            {
                "id": t.id,
                "severity": t.severity,
                "source": t.source,
                "description": t.description,
                "created_at": t.created_at
            }
            for t in threats
        ]

def main():
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    else:
        config_path = None
        
    agent = SentinelAgent(config_path)
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # Signal handling
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(agent.shutdown()))

    try:
        loop.run_until_complete(agent.run())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()

if __name__ == "__main__":
    main()
