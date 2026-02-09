import re
from typing import Optional
from datetime import datetime, timezone

from .base import LogParser, ParsedEvent

# Combined Log Format regex
# 127.0.0.1 - - [10/oct/2020:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"
COMBINED_LOG_PATTERN = re.compile(
    r'(?P<remote_addr>[\d\.]+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<body_bytes_sent>\d+) "(?P<http_referer>[^"]+)" "(?P<http_user_agent>[^"]+)"'
)

class NginxParser(LogParser):
    def __init__(self):
        super().__init__("nginx")

    def parse(self, line: str, timestamp: float) -> Optional[ParsedEvent]:
        match = COMBINED_LOG_PATTERN.match(line)
        if not match:
            return None
            
        data = match.groupdict()
        
        # Extract method and path from request
        request_parts = data.get("request", "").split()
        if len(request_parts) >= 2:
            data["method"] = request_parts[0]
            data["path"] = request_parts[1]
            data["protocol"] = request_parts[2] if len(request_parts) > 2 else ""
            
        return ParsedEvent(
            source="nginx",
            timestamp=timestamp,  # Ideally parse time_local, but using ingestion time for simplicity for now
            raw=line,
            data=data,
            type="access",
        )
