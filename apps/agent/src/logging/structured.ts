/**
 * Structured JSON Logger
 *
 * Emits structured security events to a .jsonl file.
 * Append-only, rotated by size (default 10MB).
 */

import * as fs from 'fs';
import * as path from 'path';
import { log, SENTINEL_DATA_DIR } from '@sentinel/core';

const SECURITY_LOG = path.join(SENTINEL_DATA_DIR, 'security.jsonl');
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const ROTATED_SUFFIX = '.1';

export interface SecurityEvent {
    timestamp: string;
    real_ip: string;
    proxy_ip: string | null;
    method: string | null;
    endpoint: string | null;
    user_agent: string | null;
    risk: string;
    action: string;
    reason: string;
    source: string;
    [key: string]: unknown; // extensible
}

let fd: number | null = null;

function ensureOpen(): void {
    if (fd !== null) return;
    try {
        const dir = path.dirname(SECURITY_LOG);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fd = fs.openSync(SECURITY_LOG, 'a');
    } catch (e) {
        log(`[StructuredLog] ⚠️ Failed to open log file: ${e}`);
    }
}

function rotateIfNeeded(): void {
    try {
        if (!fs.existsSync(SECURITY_LOG)) return;
        const stats = fs.statSync(SECURITY_LOG);
        if (stats.size >= MAX_FILE_SIZE) {
            if (fd !== null) { fs.closeSync(fd); fd = null; }
            const rotated = SECURITY_LOG + ROTATED_SUFFIX;
            if (fs.existsSync(rotated)) fs.unlinkSync(rotated);
            fs.renameSync(SECURITY_LOG, rotated);
            log(`[StructuredLog] 🔄 Rotated security log (${(stats.size / 1024 / 1024).toFixed(1)}MB).`);
        }
    } catch (e) {
        log(`[StructuredLog] ⚠️ Rotation error: ${e}`);
    }
}

/**
 * Emit a structured security event to the JSONL log.
 */
export function emitSecurityEvent(event: SecurityEvent): void {
    rotateIfNeeded();
    ensureOpen();
    if (fd === null) return;

    try {
        const line = JSON.stringify(event) + '\n';
        fs.writeSync(fd, line);
    } catch (e) {
        log(`[StructuredLog] ⚠️ Write error: ${e}`);
        fd = null;  // Force re-open on next write
    }
}

/**
 * Read recent security events (tail).
 */
export function readRecentEvents(count: number = 50): SecurityEvent[] {
    if (!fs.existsSync(SECURITY_LOG)) return [];
    try {
        const content = fs.readFileSync(SECURITY_LOG, 'utf-8');
        const lines = content.trim().split('\n').filter(l => l);
        const tail = lines.slice(-count);
        return tail.map(l => JSON.parse(l) as SecurityEvent);
    } catch (e) {
        return [];
    }
}
