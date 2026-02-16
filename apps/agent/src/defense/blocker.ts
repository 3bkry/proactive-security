/**
 * Progressive Blocker — Replaces the old BanManager.
 *
 * Strategy:
 *  - 1st offense → log only
 *  - 2nd+ offense within 60s → temp block (10–30 min)
 *  - HIGH/CRITICAL severity → immediate block
 *  - 3+ temp blocks → permanent block
 *
 * Safety:
 *  - Never bans Cloudflare IPs
 *  - Never bans verified bots
 *  - Never bans whitelisted/loopback/self IPs
 */

import { exec } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import { log, CONFIG_FILE, SENTINEL_DATA_DIR } from '@sentinel/core';
import * as path from 'path';
import { isCloudflareIP } from '../ip/cloudflare.js';
import { isVerifiedBot } from '../bots/verifier.js';
import type { BlockAction, BlockRecord, DefenseConfig, OffenseEntry } from './types.js';
import { DEFAULT_DEFENSE_CONFIG } from './types.js';

const BLOCK_RECORDS_FILE = path.join(SENTINEL_DATA_DIR, 'block_records.json');

export class Blocker {
    private offenses: Map<string, OffenseEntry> = new Map();
    private activeBlocks: Map<string, BlockRecord> = new Map();
    private tempBlockCounts: Map<string, number> = new Map();
    private config: DefenseConfig;
    private whitelistIPs: Set<string>;
    private _dryRun: boolean = false;

    constructor(config?: Partial<DefenseConfig>, dryRun: boolean = false) {
        this.config = { ...DEFAULT_DEFENSE_CONFIG, ...config };
        this.whitelistIPs = new Set(this.config.whitelistIPs);
        this._dryRun = dryRun;
        this.loadState();

        // Cleanup expired blocks every 60 seconds
        const cleanup = setInterval(() => this.cleanupExpired(), 60 * 1000);
        if (cleanup && typeof cleanup === 'object' && 'unref' in cleanup) cleanup.unref();

        if (this._dryRun) {
            log('[Blocker] 🔶 DRY RUN MODE: iptables enforcement disabled. Alerts and tracking only.');
        }
    }

    get dryRun(): boolean { return this._dryRun; }

    setDryRun(enabled: boolean): void {
        this._dryRun = enabled;
        log(`[Blocker] ${enabled ? '🔶 DRY RUN enabled — iptables disabled' : '🟢 DRY RUN disabled — iptables enforcement active'}`);
    }

    // ── Whitelist Management ──────────────────────────────────────

    addToWhitelist(ip: string): boolean {
        if (this.whitelistIPs.has(ip)) return false;
        this.whitelistIPs.add(ip);
        this.config.whitelistIPs = [...this.whitelistIPs];
        this.persistWhitelist();
        // If currently blocked, unblock
        if (this.activeBlocks.has(ip)) {
            this.unblock(ip);
        }
        log(`[Blocker] ✅ Added ${ip} to whitelist.`);
        return true;
    }

    removeFromWhitelist(ip: string): boolean {
        if (!this.whitelistIPs.has(ip)) return false;
        this.whitelistIPs.delete(ip);
        this.config.whitelistIPs = [...this.whitelistIPs];
        this.persistWhitelist();
        log(`[Blocker] 🗑️ Removed ${ip} from whitelist.`);
        return true;
    }

    getWhitelist(): string[] {
        return [...this.whitelistIPs];
    }

    isWhitelisted(ip: string): boolean {
        return this.whitelistIPs.has(ip);
    }

    private persistWhitelist(): void {
        try {
            if (fs.existsSync(CONFIG_FILE)) {
                const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
                config.WHITELIST_IPS = this.config.whitelistIPs;
                fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
            }
        } catch (e) {
            log(`[Blocker] ⚠️ Failed to persist whitelist: ${e}`);
        }
    }

    // ── Core Decision Engine ──────────────────────────────────────

    /**
     * Evaluate an IP event and decide what action to take.
     * Returns the action taken, or null if the IP should be skipped.
     */
    async evaluate(params: {
        ip: string;
        realIP: string;
        proxyIP: string | null;
        userAgent: string | null;
        endpoint: string | null;
        method: string | null;
        risk: string;
        reason: string;
        source: string;
        immediate?: boolean;
    }): Promise<{ action: BlockAction; record: BlockRecord } | null> {
        const { realIP, risk, immediate } = params;

        // ── Safety Checks ──
        if (await this.isSafe(realIP, params.userAgent)) return null;

        // Already permanently blocked → skip
        const existing = this.activeBlocks.get(realIP);
        if (existing && existing.action === 'perm_block' && existing.expiresAt === null) {
            return null;
        }

        // ── Determine Action ──
        let action: BlockAction;

        if (immediate || risk === 'CRITICAL' || risk === 'HIGH') {
            // High severity → immediate block
            const tempCount = this.tempBlockCounts.get(realIP) || 0;
            if (risk === 'CRITICAL' || tempCount >= this.config.permBlockAfterTempBlocks) {
                action = 'perm_block';
            } else {
                action = 'temp_block';
                this.tempBlockCounts.set(realIP, tempCount + 1);
            }
        } else {
            // Progressive: check offense history
            const now = Date.now();
            const offense = this.offenses.get(realIP);

            if (!offense || (now - offense.lastSeen > this.config.offenseWindowSec * 1000)) {
                // First offense (or outside window) → log only
                this.offenses.set(realIP, {
                    count: 1,
                    firstSeen: now,
                    lastSeen: now,
                    actions: ['logged'],
                });
                action = 'logged';
            } else {
                // Repeated offense within window → temp block
                offense.count++;
                offense.lastSeen = now;
                offense.actions.push('temp_block');
                this.offenses.set(realIP, offense);

                const tempCount = (this.tempBlockCounts.get(realIP) || 0) + 1;
                this.tempBlockCounts.set(realIP, tempCount);

                if (tempCount >= this.config.permBlockAfterTempBlocks) {
                    action = 'perm_block';
                } else {
                    action = 'temp_block';
                }
            }
        }

        // ── Build Record ──
        const record: BlockRecord = {
            ip: params.ip,
            realIP: params.realIP,
            proxyIP: params.proxyIP,
            userAgent: params.userAgent,
            endpoint: params.endpoint,
            method: params.method,
            timestamp: Date.now(),
            action,
            reason: params.reason,
            risk: params.risk,
            source: params.source,
            expiresAt: action === 'temp_block'
                ? Date.now() + this.randomTempBlockDuration()
                : action === 'perm_block' ? null : null,
        };

        // ── Execute ──
        if (action === 'temp_block' || action === 'perm_block') {
            this.activeBlocks.set(realIP, record);
            if (this._dryRun) {
                log(`[Blocker] 🔶 DRY RUN: Would ${action} ${realIP} — skipping iptables`);
            } else {
                this.executeBlock(realIP);
            }
            this.saveState();
        }

        return { action, record };
    }

    private randomTempBlockDuration(): number {
        const min = this.config.tempBlockDurationMin * 60 * 1000;
        const max = this.config.tempBlockDurationMax * 60 * 1000;
        return Math.floor(Math.random() * (max - min)) + min;
    }

    // ── Safety Checks ──────────────────────────────────────────────

    private async isSafe(ip: string, userAgent: string | null): Promise<boolean> {
        // Loopback
        if (ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0' || ip === 'localhost') {
            return true;
        }

        // Self-IP
        const nets = os.networkInterfaces();
        for (const name of Object.keys(nets)) {
            for (const net of nets[name] || []) {
                if (net.address === ip) return true;
            }
        }

        // Whitelist
        if (this.whitelistIPs.has(ip)) return true;

        // Cloudflare IP (never ban proxy IPs)
        if (isCloudflareIP(ip)) {
            log(`[Blocker] 🛡️ SAFETY: Skipping Cloudflare proxy IP ${ip}`);
            return true;
        }

        // Verified search bot
        if (userAgent && this.looksLikeBot(userAgent)) {
            const verified = await isVerifiedBot(ip, userAgent);
            if (verified) {
                log(`[Blocker] 🤖 SAFETY: Verified bot detected, skipping ${ip}`);
                return true;
            }
        }

        return false;
    }

    private looksLikeBot(ua: string): boolean {
        return /googlebot|bingbot|slurp|duckduckbot/i.test(ua);
    }

    // ── Firewall Execution ─────────────────────────────────────────

    private executeBlock(ip: string): void {
        // Allowlist safety rules first
        const safetyRules = [
            `iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`,
            `iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -A INPUT -i lo -j ACCEPT`,
            `iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 22 -j ACCEPT`,
        ];

        const banCmd = `iptables -C INPUT -s ${ip} -j DROP 2>/dev/null || iptables -I INPUT 1 -s ${ip} -j DROP`;
        const dockerCmd = `iptables -C DOCKER-USER -s ${ip} -j DROP 2>/dev/null || (iptables -L DOCKER-USER >/dev/null 2>&1 && iptables -I DOCKER-USER 1 -s ${ip} -j DROP)`;

        exec(banCmd, (error: Error | null) => {
            if (error) {
                log(`[Blocker] ⚠️ Failed to block ${ip}: ${error.message}. (Ensure agent runs as root)`);
            } else {
                exec(safetyRules.join(' && '), (safeErr: Error | null) => {
                    if (safeErr) log(`[Blocker] ⚠️ Safety allowlist error: ${safeErr.message}`);
                });
                exec(dockerCmd, () => { /* ok if docker chain missing */ });
            }
        });
    }

    async unblock(ip: string): Promise<boolean> {
        if (!this.activeBlocks.has(ip)) return false;

        log(`[Blocker] 🔓 Unblocking IP: ${ip}`);
        if (!this._dryRun) {
            exec(`iptables -D INPUT -s ${ip} -j DROP 2>/dev/null; iptables -D DOCKER-USER -s ${ip} -j DROP 2>/dev/null`,
                (error: Error | null) => {
                    if (error) log(`[Blocker] ⚠️ Unblock error for ${ip}: ${error.message}`);
                });
        } else {
            log(`[Blocker] 🔶 DRY RUN: Would unblock ${ip} — skipping iptables`);
        }

        this.activeBlocks.delete(ip);
        this.offenses.delete(ip);
        this.tempBlockCounts.delete(ip);
        this.saveState();
        return true;
    }

    // ── Queries ─────────────────────────────────────────────────────

    isBlocked(ip: string): boolean {
        return this.activeBlocks.has(ip);
    }

    getBlockedIPs(): string[] {
        return [...this.activeBlocks.keys()];
    }

    getBlockRecords(): BlockRecord[] {
        return [...this.activeBlocks.values()];
    }

    // ── Persistence ─────────────────────────────────────────────────

    private saveState(): void {
        try {
            const dir = path.dirname(BLOCK_RECORDS_FILE);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            const data = {
                activeBlocks: Object.fromEntries(this.activeBlocks),
                tempBlockCounts: Object.fromEntries(this.tempBlockCounts),
            };
            fs.writeFileSync(BLOCK_RECORDS_FILE, JSON.stringify(data, null, 2));
        } catch (e) {
            log(`[Blocker] ⚠️ Failed to save state: ${e}`);
        }
    }

    private loadState(): void {
        if (!fs.existsSync(BLOCK_RECORDS_FILE)) return;
        try {
            const data = JSON.parse(fs.readFileSync(BLOCK_RECORDS_FILE, 'utf-8'));
            if (data.activeBlocks) {
                for (const [ip, record] of Object.entries(data.activeBlocks)) {
                    this.activeBlocks.set(ip, record as BlockRecord);
                    if (!this._dryRun) {
                        this.executeBlock(ip);
                    }
                }
            }
            if (data.tempBlockCounts) {
                for (const [ip, count] of Object.entries(data.tempBlockCounts)) {
                    this.tempBlockCounts.set(ip, count as number);
                }
            }
            log(`[Blocker] Loaded ${this.activeBlocks.size} active blocks from state.`);
        } catch (e) {
            log(`[Blocker] ⚠️ Failed to load state: ${e}`);
        }

        // Load whitelist from config
        try {
            if (fs.existsSync(CONFIG_FILE)) {
                const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
                if (config.WHITELIST_IPS && Array.isArray(config.WHITELIST_IPS)) {
                    for (const ip of config.WHITELIST_IPS) {
                        this.whitelistIPs.add(ip);
                    }
                }
            }
        } catch (e) { /* ok */ }
    }

    // ── Cleanup ─────────────────────────────────────────────────────

    private cleanupExpired(): void {
        const now = Date.now();
        for (const [ip, record] of this.activeBlocks.entries()) {
            if (record.expiresAt && now > record.expiresAt) {
                log(`[Blocker] ⏰ Temp block expired for ${ip}. Unblocking.`);
                this.unblock(ip);
            }
        }

        // Clean stale offense entries (older than 10x the window)
        const staleThreshold = this.config.offenseWindowSec * 10 * 1000;
        for (const [ip, entry] of this.offenses.entries()) {
            if (now - entry.lastSeen > staleThreshold) {
                this.offenses.delete(ip);
            }
        }
    }
}
