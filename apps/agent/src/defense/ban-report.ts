/**
 * Ban Report — Forensic log of every ban action with the raw log line that triggered it.
 *
 * Stored as a JSON array in ~/.sentinel/ban_reports.json.
 * Accessible via Telegram /report command.
 */

import * as fs from 'fs';
import * as path from 'path';
import { log, SENTINEL_DATA_DIR } from '@sentinel/core';

export interface BanReportEntry {
    /** When the ban was applied */
    timestamp: string;
    /** The banned IP */
    ip: string;
    /** Block type: temp_block or perm_block */
    action: string;
    /** Risk level that triggered the ban */
    risk: string;
    /** Human-readable reason (OWASP category, rate limit, etc.) */
    reason: string;
    /** Threat score at time of ban */
    score: number;
    /** Number of events that contributed to the score */
    eventCount: number;
    /** Blocking method used (iptables, cloudflare_api, etc.) */
    blockMethod: string;
    /** Log source file (e.g. /var/log/nginx/access.log) */
    source: string;
    /** The raw log line that triggered the final ban */
    rawLogLine: string;
    /** HTTP endpoint if available */
    endpoint: string | null;
    /** HTTP method if available */
    method: string | null;
    /** User-Agent if available */
    userAgent: string | null;
}

const REPORT_FILE = path.join(SENTINEL_DATA_DIR, 'ban_reports.json');
const MAX_REPORTS = 500; // Keep last 500 ban entries

let reports: BanReportEntry[] = [];

/** Load reports from disk */
export function loadBanReports(): void {
    try {
        if (fs.existsSync(REPORT_FILE)) {
            const data = JSON.parse(fs.readFileSync(REPORT_FILE, 'utf-8'));
            if (Array.isArray(data)) {
                reports = data;
                log(`[BanReport] Loaded ${reports.length} ban report entries.`);
            }
        }
    } catch (e) {
        log(`[BanReport] ⚠️ Failed to load reports: ${e}`);
    }
}

/** Persist reports to disk */
function persistReports(): void {
    try {
        const dir = path.dirname(REPORT_FILE);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(REPORT_FILE, JSON.stringify(reports, null, 2));
    } catch (e) {
        log(`[BanReport] ⚠️ Failed to persist reports: ${e}`);
    }
}

/** Record a new ban event */
export function recordBan(entry: BanReportEntry): void {
    reports.unshift(entry); // newest first
    if (reports.length > MAX_REPORTS) {
        reports = reports.slice(0, MAX_REPORTS);
    }
    persistReports();
    log(`[BanReport] 📝 Recorded ban for ${entry.ip} (${entry.action})`);
}

/** Get recent ban reports (paginated) */
export function getRecentBans(limit: number = 50): BanReportEntry[] {
    return reports.slice(0, limit);
}

/** Get a page of ban reports (0-indexed page, pageSize entries per page) */
export function getRecentBansPage(page: number, pageSize: number = 50): { entries: BanReportEntry[]; total: number; hasMore: boolean } {
    const start = page * pageSize;
    const entries = reports.slice(start, start + pageSize);
    return { entries, total: reports.length, hasMore: start + pageSize < reports.length };
}

/** Get ban reports for a specific IP */
export function getBansForIP(ip: string): BanReportEntry[] {
    return reports.filter(r => r.ip === ip);
}

/** Get total ban count */
export function getBanCount(): number {
    return reports.length;
}

/** Full detailed format for each ban entry (plain text — no Markdown) */
export function formatReportEntry(entry: BanReportEntry, index: number): string {
    const time = new Date(entry.timestamp).toLocaleString('en-GB', { timeZone: 'Africa/Cairo' });
    const rawPreview = entry.rawLogLine.length > 200
        ? entry.rawLogLine.substring(0, 200) + '...'
        : entry.rawLogLine;

    return (
        `${index}. IP: ${entry.ip}\n` +
        `⏰ ${time}\n` +
        `🎯 Action: ${entry.action} | Risk: ${entry.risk}\n` +
        `📊 Score: ${Math.round(entry.score)} (${entry.eventCount} events)\n` +
        `🔒 Method: ${entry.blockMethod}\n` +
        `📌 Reason: ${entry.reason}\n` +
        `📂 Source: ${entry.source}\n` +
        `📝 Raw Log:\n${rawPreview}`
    );
}
