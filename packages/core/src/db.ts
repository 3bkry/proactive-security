import Database from "better-sqlite3";
import { Threat, LogEvent } from "./types";

export class SentinelDB {
    private db: Database.Database;

    constructor(path: string) {
        this.db = new Database(path);
        this.initialize();
    }

    private initialize() {
        this.db.exec(`
      CREATE TABLE IF NOT EXISTS threats (
        id TEXT PRIMARY KEY,
        severity TEXT,
        source_ip TEXT,
        description TEXT,
        timestamp TEXT,
        raw_log TEXT,
        rule_id TEXT
      );
      
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT,
        timestamp TEXT,
        raw TEXT
      );
    `);
    }

    public saveThreat(threat: Threat) {
        const stmt = this.db.prepare(`
      INSERT INTO threats (id, severity, source_ip, description, timestamp, raw_log, rule_id)
      VALUES (@id, @severity, @source_ip, @description, @timestamp, @raw_log, @rule_id)
    `);
        stmt.run({
            ...threat,
            timestamp: threat.timestamp.toISOString(),
        });
    }

    public saveEvent(event: LogEvent) {
        const stmt = this.db.prepare(`
      INSERT INTO events (source, timestamp, raw)
      VALUES (@source, @timestamp, @raw)
    `);
        stmt.run({
            ...event,
            timestamp: event.timestamp.toISOString(),
        });
    }

    public getThreats(limit = 10): Threat[] {
        const stmt = this.db.prepare("SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?");
        const rows = stmt.all(limit) as any[];
        return rows.map(row => ({
            ...row,
            timestamp: new Date(row.timestamp),
        }));
    }
}
