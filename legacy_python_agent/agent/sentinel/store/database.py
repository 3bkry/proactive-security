import aiosqlite
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from .models import Threat, Action

class ThreatStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None

    async def initialize(self):
        """Initialize database connection and tables."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._create_tables()

    async def close(self):
        if self._db:
            await self._db.close()

    async def _create_tables(self):
        schema = """
        CREATE TABLE IF NOT EXISTS threats (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            source TEXT NOT NULL,
            severity TEXT NOT NULL,
            type TEXT NOT NULL,
            attacker_ip TEXT,
            attacker_geo TEXT,
            description TEXT NOT NULL,
            raw_log TEXT,
            risk_score REAL NOT NULL,
            rule_id TEXT,
            anomaly_score REAL,
            llm_explanation TEXT,
            status TEXT DEFAULT 'open',
            resolved_at TEXT,
            resolved_by TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_threats_created ON threats(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
        CREATE INDEX IF NOT EXISTS idx_threats_ip ON threats(attacker_ip);

        CREATE TABLE IF NOT EXISTS actions (
            id TEXT PRIMARY KEY,
            threat_id TEXT NOT NULL REFERENCES threats(id),
            created_at TEXT NOT NULL,
            type TEXT NOT NULL,
            target_ip TEXT,
            duration INTEGER,
            expires_at TEXT,
            status TEXT DEFAULT 'active',
            revoked_by TEXT,
            revoked_at TEXT
        );
        
        CREATE INDEX IF NOT EXISTS idx_actions_threat ON actions(threat_id);
        CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status);

        CREATE TABLE IF NOT EXISTS log_sources (
            id TEXT PRIMARY KEY,
            path TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            last_offset INTEGER DEFAULT 0,
            last_inode INTEGER,
            discovered_at TEXT NOT NULL,
            last_event_at TEXT
        );
        """
        await self._db.executescript(schema)
        await self._db.commit()

    async def save_threat(self, threat: Threat):
        query = """
        INSERT INTO threats (
            id, created_at, source, severity, type, attacker_ip, attacker_geo,
            description, raw_log, risk_score, rule_id, anomaly_score,
            llm_explanation, status, resolved_at, resolved_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        await self._db.execute(query, (
            threat.id, threat.created_at, threat.source, threat.severity,
            threat.type, threat.attacker_ip, threat.attacker_geo,
            threat.description, threat.raw_log, threat.risk_score,
            threat.rule_id, threat.anomaly_score, threat.llm_explanation,
            threat.status, threat.resolved_at, threat.resolved_by
        ))
        await self._db.commit()

    async def save_action(self, action: Action):
        query = """
        INSERT INTO actions (
            id, threat_id, created_at, type, target_ip, duration,
            expires_at, status, revoked_by, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        await self._db.execute(query, (
            action.id, action.threat_id, action.created_at, action.type,
            action.target_ip, action.duration, action.expires_at,
            action.status, action.revoked_by, action.revoked_at
        ))
        await self._db.commit()

    async def get_threats(self, limit: int = 50) -> List[Threat]:
        async with self._db.execute(
            "SELECT * FROM threats ORDER BY created_at DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [Threat(**dict(row)) for row in rows]
