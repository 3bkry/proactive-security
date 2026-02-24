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

      CREATE VIRTUAL TABLE IF NOT EXISTS log_index USING fts5(
        content,
        source UNINDEXED,
        timestamp UNINDEXED
      );
      
      CREATE TABLE IF NOT EXISTS blocks (
        ip TEXT PRIMARY KEY,
        realIP TEXT,
        proxyIP TEXT,
        userAgent TEXT,
        method TEXT,
        endpoint TEXT,
        timestamp INTEGER,
        action TEXT,
        reason TEXT,
        risk TEXT,
        source TEXT,
        expiresAt INTEGER,
        blockMethod TEXT,
        cfRuleId TEXT
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

  public indexLog(line: string, source: string) {
    const stmt = this.db.prepare(`
            INSERT INTO log_index (content, source, timestamp)
            VALUES (?, ?, ?)
        `);
    stmt.run(line, source, new Date().toISOString());
  }

  public searchLogs(query: string, limit = 50): any[] {
    const stmt = this.db.prepare(`
            SELECT * FROM log_index 
            WHERE content MATCH ? 
            ORDER BY rowid DESC 
            LIMIT ?
        `);
    return stmt.all(query, limit);
  }

  public getThreats(limit = 10): Threat[] {
    const stmt = this.db.prepare("SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?");
    const rows = stmt.all(limit) as any[];
    return rows.map(row => ({
      ...row,
      timestamp: new Date(row.timestamp),
    }));
  }

  public saveBlock(record: any) {
    const stmt = this.db.prepare(`
        INSERT OR REPLACE INTO blocks (
            ip, realIP, proxyIP, userAgent, method, endpoint, 
            timestamp, action, reason, risk, source, expiresAt, blockMethod, cfRuleId
        ) VALUES (
            @ip, @realIP, @proxyIP, @userAgent, @method, @endpoint, 
            @timestamp, @action, @reason, @risk, @source, @expiresAt, @blockMethod, @cfRuleId
        )
    `);

    // Convert boolean 'action' back to stored string if needed, or keep it as is.
    // The previous BlockRecord type had string 'action', we are flexible here.
    const sqlRecord = {
      ip: record.ip || null,
      realIP: record.realIP ?? null,
      proxyIP: record.proxyIP ?? null,
      userAgent: record.userAgent ?? null,
      method: record.method ?? null,
      endpoint: record.endpoint ?? null,
      timestamp: record.timestamp || Date.now(),
      action: record.action || 'perm_block',
      reason: record.reason ?? null,
      risk: record.risk ?? null,
      source: record.source ?? null,
      expiresAt: record.expiresAt || null,
      blockMethod: record.blockMethod ?? null,
      cfRuleId: record.cfRuleId || null
    };

    stmt.run(sqlRecord);
  }

  public removeBlock(ip: string) {
    const stmt = this.db.prepare("DELETE FROM blocks WHERE ip = ?");
    stmt.run(ip);
  }

  public getActiveBlocks(): Record<string, any> {
    const stmt = this.db.prepare("SELECT * FROM blocks");
    const rows = stmt.all() as any[];

    const activeBlocks: Record<string, any> = {};
    for (const row of rows) {
      // Purge expired records on load
      if (row.expiresAt && Date.now() > row.expiresAt) {
        this.removeBlock(row.ip);
        continue;
      }
      activeBlocks[row.ip] = row;
    }
    return activeBlocks;
  }
}

