from pathlib import Path
from typing import Dict, List, Set, Tuple
from ..utils.logging import get_logger

logger = get_logger("log_discovery")

DISCOVERY_MAP = {
    "ssh": [
        "/var/log/auth.log",           # Debian/Ubuntu
        "/var/log/secure",             # RHEL/CentOS
    ],
    "nginx": [
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
    ],
    "apache": [
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
    ],
    "system": [
        "/var/log/syslog",
        "/var/log/messages",
    ],
    "kernel": [
        "/var/log/kern.log",
    ],
    "firewall": [
        "/var/log/ufw.log",
    ],
}

class LogDiscovery:
    def discover(self) -> Dict[str, List[str]]:
        """
        Discover active log files on the system.
        Returns a dictionary mapping log type -> list of paths.
        """
        discovered: Dict[str, List[str]] = {}
        
        for log_type, paths in DISCOVERY_MAP.items():
            found_paths = []
            for path_str in paths:
                path = Path(path_str)
                # Handle globbing if present (e.g. /var/log/nginx/*/access.log)
                if "*" in path_str:
                    # simplistic glob handling
                    parent = Path(path_str.split("*")[0])
                    if parent.exists():
                        pattern = path_str.split(str(parent))[1].lstrip("/")
                        found_paths.extend([str(p) for p in parent.glob(pattern)])
                else:
                    if path.exists():
                        found_paths.append(str(path))
            
            if found_paths:
                discovered[log_type] = found_paths
                logger.info(f"Discovered {log_type} logs: {found_paths}")
                
        return discovered

def perform_discovery() -> Dict[str, List[str]]:
    finder = LogDiscovery()
    return finder.discover()
