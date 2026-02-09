from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid

@dataclass
class Threat:
    source: str
    severity: str
    type: str
    description: str
    attacker_ip: Optional[str] = None
    attacker_geo: Optional[str] = None
    raw_log: Optional[str] = None
    risk_score: float = 0.0
    rule_id: Optional[str] = None
    anomaly_score: Optional[float] = None
    llm_explanation: Optional[str] = None
    status: str = "open"
    id: str = field(default_factory=lambda: f"THR-{uuid.uuid4().hex[:12]}")
    created_at: str = field(default_factory=lambda: datetime.isoformat(datetime.now()))
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None

@dataclass
class Action:
    threat_id: str
    type: str
    target_ip: Optional[str] = None
    duration: Optional[int] = None
    status: str = "active"
    id: str = field(default_factory=lambda: f"ACT-{uuid.uuid4().hex[:12]}")
    created_at: str = field(default_factory=lambda: datetime.isoformat(datetime.now()))
    expires_at: Optional[str] = None
    revoked_by: Optional[str] = None
    revoked_at: Optional[str] = None
