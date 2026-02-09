from pathlib import Path

DEFAULT_CONFIG_PATH = Path("/etc/sentinel/config.yml")
DEFAULT_DB_PATH = Path("/var/lib/sentinel/sentinel.db")
DEFAULT_SOCKET_PATH = Path("/var/run/sentinel/sentinel.sock")

DEFAULT_CONFIG = {
    "agent": {
        "name": "sentinel-agent",
        "log_level": "INFO",
        "ipc_socket": str(DEFAULT_SOCKET_PATH),
    },
    "database": {
        "path": str(DEFAULT_DB_PATH),
    },
    "logs": {
        "discovery": True,
        "sources": [],  # Will be populated by discovery or user config
        "max_tail_bytes": 1024 * 1024,  # 1MB
    },
    "detection": {
        "enabled": True,
        "rules_path": "/etc/sentinel/rules",
        "anomaly": {
            "enabled": True,
            "training_period": 3600,  # 1 hour
        },
        "llm": {
            "enabled": False,
            "provider": "ollama",
            "model": "llama3",
        },
    },
    "response": {
        "enabled": True,
        "dry_run": False,  # If True, only log actions
        "default_block_duration": 3600,  # 1 hour
    },
    "notifications": {
        "enabled": False,
        "channels": {},
    },
    "cloud": {
        "enabled": False,
        "api_url": "https://api.sentinelai.local",
        "token": "",
    },
}
