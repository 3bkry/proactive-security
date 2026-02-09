import asyncio
import os
import time
from pathlib import Path
from typing import Dict, AsyncGenerator, List, Optional
from dataclasses import dataclass

from ..utils.logging import get_logger

logger = get_logger("log_watcher")

@dataclass
class LogEvent:
    source_path: str
    content: str
    timestamp: float

class FileTailer:
    """Tails a single file, handling rotation by monitoring inode."""
    
    def __init__(self, path: str, start_at_end: bool = True):
        self.path = Path(path)
        self.start_at_end = start_at_end
        self.file: Optional[AsyncGenerator] = None
        self._fd = None
        self._inode = None
        self._offset = 0

    async def open(self):
        if not self.path.exists():
            return
        
        try:
            self._fd = open(self.path, "r")
            self._inode = os.fstat(self._fd.fileno()).st_ino
            
            if self.start_at_end:
                self._fd.seek(0, 2)
                self._offset = self._fd.tell()
            else:
                self._fd.seek(0)
                self._offset = 0
                
        except Exception as e:
            logger.error(f"Failed to open {self.path}: {e}")

    async def read(self) -> AsyncGenerator[str, None]:
        if not self._fd:
            await self.open()
            if not self._fd:
                return

        while True:
            line = self._fd.readline()
            if line:
                if line.endswith("\n"):
                    yield line.strip()
                else:
                    # Incomplete line, wait for more
                    # But if we wait too long, it might be rotated.
                    # For simplicity, we yield it or buffer it?
                    # Let's yield for now if it's substantial, 
                    # but usually logs write atomically.
                    if len(line) > 0:
                        yield line.strip()
            else:
                # EOF. Check for rotation.
                try:
                    current_inode = os.stat(self.path).st_ino
                    if current_inode != self._inode:
                        logger.info(f"File rotated: {self.path}")
                        self._fd.close()
                        await self.open()
                        # Read from beginning of new file
                        continue
                except FileNotFoundError:
                    # File deleted/moved
                    pass
                    
                # No new data, return control
                break

    def close(self):
        if self._fd:
            self._fd.close()
            self._fd = None

class LogWatcher:
    """Manages multiple FileTailers and yields events."""
    
    def __init__(self, paths: List[str]):
        self.tailers: Dict[str, FileTailer] = {}
        for p in paths:
            self.add_path(p)
            
    def add_path(self, path: str):
        if path not in self.tailers:
            self.tailers[path] = FileTailer(path)

    async def watch(self) -> AsyncGenerator[LogEvent, None]:
        # Initialize
        for tailer in self.tailers.values():
            await tailer.open()

        while True:
            data_found = False
            for path, tailer in self.tailers.items():
                async for line in tailer.read():
                    if line:
                        yield LogEvent(
                            source_path=path,
                            content=line,
                            timestamp=time.time()
                        )
                        data_found = True
            
            if not data_found:
                await asyncio.sleep(0.5)  # Polling interval
