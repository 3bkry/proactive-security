from typing import Optional
from .base import LogParser, ParsedEvent

class GenericParser(LogParser):
    def __init__(self):
        super().__init__("generic")

    def parse(self, line: str, timestamp: float) -> Optional[ParsedEvent]:
        # Simple parser that wraps the raw line
        return ParsedEvent(
            source="generic",
            timestamp=timestamp,
            raw=line,
            data={"message": line},
            type="generic",
        )
