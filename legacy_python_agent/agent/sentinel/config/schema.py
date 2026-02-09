from pathlib import Path
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

from .defaults import DEFAULT_DB_PATH, DEFAULT_SOCKET_PATH

class AgentConfig(BaseModel):
    name: str = "sentinel-agent"
    log_level: str = "INFO"
    ipc_socket: str = str(DEFAULT_SOCKET_PATH)

class DatabaseConfig(BaseModel):
    path: str = str(DEFAULT_DB_PATH)

class LogSource(BaseModel):
    path: str
    type: str  # ssh, nginx, etc.
    enabled: bool = True

class LogsConfig(BaseModel):
    discovery: bool = True
    sources: List[LogSource] = Field(default_factory=list)
    max_tail_bytes: int = 1048576

class AnomalyConfig(BaseModel):
    enabled: bool = True
    training_period: int = 3600

class LLMConfig(BaseModel):
    enabled: bool = False
    provider: str = "ollama"
    model: str = "llama3"

class DetectionConfig(BaseModel):
    enabled: bool = True
    rules_path: str = "/etc/sentinel/rules"
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)

class ResponseConfig(BaseModel):
    enabled: bool = True
    dry_run: bool = False
    default_block_duration: int = 3600

class NotificationChannel(BaseModel):
    type: str
    config: Dict[str, Any]

class NotificationsConfig(BaseModel):
    enabled: bool = False
    channels: Dict[str, NotificationChannel] = Field(default_factory=dict)

class CloudConfig(BaseModel):
    enabled: bool = False
    api_url: str = "https://api.sentinelai.local"
    token: str = ""

class SentinelConfig(BaseModel):
    agent: AgentConfig = Field(default_factory=AgentConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    logs: LogsConfig = Field(default_factory=LogsConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    cloud: CloudConfig = Field(default_factory=CloudConfig)
