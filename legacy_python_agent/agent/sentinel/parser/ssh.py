import re
from typing import Optional
from .base import LogParser, ParsedEvent

class SSHParser(LogParser):
    def __init__(self):
        super().__init__("ssh")
        
        # Common SSH patterns
        self.patterns = [
            # Failed password for invalid user admin from 192.168.1.1 port 55555 ssh2
            re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d\.]+) port \d+ ssh2"),
            # Disconnected from invalid user admin 192.168.1.1 port 55555 [preauth]
            re.compile(r"Disconnected from (invalid user )?(?P<user>\S+) (?P<ip>[\d\.]+) port \d+ \[preauth\]"),
            # Accepted password for user from ...
            re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>[\d\.]+) port \d+ ssh2"),
        ]

    def parse(self, line: str, timestamp: float) -> Optional[ParsedEvent]:
        # Only parse lines related to sshd
        if "sshd[" not in line:
            return None

        event_data = {}
        for pattern in self.patterns:
            match = pattern.search(line)
            if match:
                event_data = match.groupdict()
                break
        
        if not event_data:
            return None # Or return generic ssh event?

        return ParsedEvent(
            source="ssh",
            timestamp=timestamp,
            raw=line,
            data=event_data,
            type="auth",
        )
