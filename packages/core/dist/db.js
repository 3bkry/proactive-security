"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SentinelDB = void 0;
const better_sqlite3_1 = __importDefault(require("better-sqlite3"));
class SentinelDB {
    db;
    constructor(path) {
        this.db = new better_sqlite3_1.default(path);
        this.initialize();
    }
    initialize() {
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

      CREATE VIRTUAL TABLE IF NOT EXISTS log_index USING fts5(
        content,
        source UNINDEXED,
        timestamp UNINDEXED
      );
    `);
    }
    saveThreat(threat) {
        const stmt = this.db.prepare(`
      INSERT INTO threats (id, severity, source_ip, description, timestamp, raw_log, rule_id)
      VALUES (@id, @severity, @source_ip, @description, @timestamp, @raw_log, @rule_id)
    `);
        stmt.run({
            ...threat,
            timestamp: threat.timestamp.toISOString(),
        });
    }
    saveEvent(event) {
        const stmt = this.db.prepare(`
      INSERT INTO events (source, timestamp, raw)
      VALUES (@source, @timestamp, @raw)
    `);
        stmt.run({
            ...event,
            timestamp: event.timestamp.toISOString(),
        });
    }
    indexLog(line, source) {
        const stmt = this.db.prepare(`
            INSERT INTO log_index (content, source, timestamp)
            VALUES (?, ?, ?)
        `);
        stmt.run(line, source, new Date().toISOString());
    }
    searchLogs(query, limit = 50) {
        const stmt = this.db.prepare(`
            SELECT * FROM log_index 
            WHERE content MATCH ? 
            ORDER BY rowid DESC 
            LIMIT ?
        `);
        return stmt.all(query, limit);
    }
    getThreats(limit = 10) {
        const stmt = this.db.prepare("SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?");
        const rows = stmt.all(limit);
        return rows.map(row => ({
            ...row,
            timestamp: new Date(row.timestamp),
        }));
    }
}
exports.SentinelDB = SentinelDB;
//# sourceMappingURL=db.js.map