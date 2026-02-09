from abc import ABC, abstractmethod
from typing import Dict, Optional, Any
from dataclasses import dataclass

@dataclass
class ParsedEvent:
    source: str
    timestamp: float
    raw: str
    data: Dict[str, Any]
    type: str  # nginx, ssh, etc.

class LogParser(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def parse(self, line: str, timestamp: float) -> Optional[ParsedEvent]:
        """Parse a log line into a structured event."""
        pass
