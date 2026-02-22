/**
 * Progressive Blocker — Smart multi-method IP blocking.
 *
 * Strategy:
 *  - 1st offense → log only
 *  - 2nd+ offense within 60s → temp block (10–30 min)
 *  - HIGH/CRITICAL severity → immediate block
 *  - 3+ temp blocks → permanent block
 *
 * Blocking Method Selection:
 *  - If CF API key configured → Cloudflare API (blocks globally before reaching server)
 *  - If behind CF, no API key → Nginx/Apache deny rules (blocks at application layer)
 *  - If not behind CF → iptables (blocks at network layer)
 *
 * Safety:
 *  - Never bans Cloudflare IPs
 *  - Never bans verified bots
 *  - Never bans whitelisted/loopback/self IPs
 *  - Each block record saves its method for correct reversal
 */

import { exec } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import { log, CONFIG_FILE, SENTINEL_DATA_DIR } from '@sentinel/core';
import * as path from 'path';
import { isCloudflareIP } from '../ip/cloudflare.js';
import { isVerifiedBot } from '../bots/verifier.js';
import { CloudflareBlocker, type CloudflareAPIConfig } from '../ip/cloudflare-api.js';
import { WebServerDenyManager, detectWebServer, type WebServerType } from './webserver-deny.js';
import type { BlockAction, BlockMethod, BlockRecord, DefenseConfig, OffenseEntry } from './types.js';
import { DEFAULT_DEFENSE_CONFIG } from './types.js';

const BLOCK_RECORDS_FILE = path.join(SENTINEL_DATA_DIR, 'block_records.json');

export interface BlockerConfig {
    defense?: Partial<DefenseConfig>;
    dryRun?: boolean;
    cloudflareAPI?: CloudflareAPIConfig;
}

export class Blocker {
    private offenses: Map<string, OffenseEntry> = new Map();
    private activeBlocks: Map<string, BlockRecord> = new Map();
    private tempBlockCounts: Map<string, number> = new Map();
    private config: DefenseConfig;
    private whitelistIPs: Set<string>;
    private _dryRun: boolean = false;

    // Blocking backends
    private cfBlocker: CloudflareBlocker | null = null;
    private webDenyManager: WebServerDenyManager | null = null;
    private detectedWebServer: WebServerType = null;

    constructor(configOrDefense?: Partial<DefenseConfig> | BlockerConfig, dryRun?: boolean) {
        // Support both old signature (DefenseConfig, dryRun) and new (BlockerConfig)
        let defenseConfig: Partial<DefenseConfig> = {};
        let cfConfig: CloudflareAPIConfig | undefined;

        if (configOrDefense && 'defense' in configOrDefense) {
            // New BlockerConfig format
            const bc = configOrDefense as BlockerConfig;
            defenseConfig = bc.defense || {};
            this._dryRun = bc.dryRun || false;
            cfConfig = bc.cloudflareAPI;
        } else {
            // Old format: (DefenseConfig, dryRun)
            defenseConfig = (configOrDefense as Partial<DefenseConfig>) || {};
            this._dryRun = dryRun || false;
        }

        this.config = { ...DEFAULT_DEFENSE_CONFIG, ...defenseConfig };
        this.whitelistIPs = new Set(this.config.whitelistIPs);

        // Initialize blocking backends
        if (cfConfig && ((cfConfig.apiKey && cfConfig.email) || (cfConfig.apiToken && cfConfig.zoneId))) {
            this.cfBlocker = new CloudflareBlocker(cfConfig);
        }

        this.detectedWebServer = detectWebServer();
        if (this.detectedWebServer) {
            this.webDenyManager = new WebServerDenyManager(this.detectedWebServer);
        }

        this.loadState();

        // Cleanup expired blocks every 60 seconds
        const cleanup = setInterval(() => this.cleanupExpired(), 60 * 1000);
        if (cleanup && typeof cleanup === 'object' && 'unref' in cleanup) cleanup.unref();

        // Startup logging
        if (this._dryRun) {
            log('[Blocker] 🔶 DRY RUN MODE: All enforcement disabled. Alerts and tracking only.');
        }

        log(`[Blocker] Blocking methods available:`);
        log(`  • Cloudflare API: ${this.cfBlocker ? '✅ configured' : '❌ not configured'}`);
        log(`  • Web server deny: ${this.webDenyManager ? `✅ ${this.detectedWebServer}` : '❌ not detected'}`);
        log(`  • iptables: ✅ always available (for non-proxied traffic)`);
    }

    get dryRun(): boolean { return this._dryRun; }

    setDryRun(enabled: boolean): void {
        this._dryRun = enabled;
        log(`[Blocker] ${enabled ? '🔶 DRY RUN enabled — all enforcement disabled' : '🟢 DRY RUN disabled — enforcement active'}`);
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

    // ── Block Method Selection ────────────────────────────────────

    /**
     * Choose the right blocking method based on the traffic path.
     *
     * Decision tree:
     *  1. If CF API configured → always use CF API (blocks globally)
     *  2. If proxyIP is a Cloudflare IP → use web server deny (iptables won't work)
     *  3. Otherwise → use iptables (direct traffic, most effective)
     */
    private selectBlockMethod(proxyIP: string | null): BlockMethod {
        // If Cloudflare API is configured, always prefer it
        if (this.cfBlocker) {
            return 'cloudflare_api';
        }

        // If the proxy is Cloudflare, iptables can't help — use web server deny rules
        if (proxyIP && isCloudflareIP(proxyIP)) {
            if (this.webDenyManager) {
                return this.detectedWebServer === 'apache' ? 'apache_deny' : 'nginx_deny';
            }
            // No web server detected — log warning, fall through to iptables (won't be effective)
            log(`[Blocker] ⚠️ Behind Cloudflare but no web server or CF API configured — iptables block will be ineffective!`);
        }

        return 'iptables';
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
            // Determine action severity
            const tempCount = this.tempBlockCounts.get(realIP) || 0;
            if (risk === 'CRITICAL') {
                // CRITICAL = always permanent (e.g. known exploit payloads)
                action = 'perm_block';
            } else if (tempCount >= this.config.permBlockAfterTempBlocks) {
                // Repeated offender → escalate to permanent
                action = 'perm_block';
            } else {
                // HIGH / immediate → temp block first
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

        // ── Select Blocking Method ──
        const blockMethod = this.selectBlockMethod(params.proxyIP);

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
            blockMethod,
        };

        // ── Execute ──
        if (action === 'temp_block' || action === 'perm_block') {
            this.activeBlocks.set(realIP, record);
            if (this._dryRun) {
                log(`[Blocker] 🔶 DRY RUN: Would ${action} ${realIP} via ${blockMethod} — skipping`);
            } else {
                await this.executeBlock(realIP, blockMethod, params.reason, record);
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

    // ── Blocking Execution ─────────────────────────────────────────

    /**
     * Execute a block using the primary method + always add iptables too.
     * Defense in depth: even if CF or nginx blocks, iptables is an extra layer.
     */
    private async executeBlock(ip: string, method: BlockMethod, reason: string, record: BlockRecord): Promise<void> {
        // 1. Primary method
        switch (method) {
            case 'cloudflare_api': {
                if (this.cfBlocker) {
                    const ruleId = await this.cfBlocker.blockIP(ip, reason);
                    if (ruleId) record.cfRuleId = ruleId;
                }
                break;
            }

            case 'nginx_deny':
            case 'apache_deny': {
                if (this.webDenyManager) {
                    await this.webDenyManager.addDeny(ip);
                }
                break;
            }
        }

        // 2. Always add iptables as well (defense in depth)
        this.executeIptablesBlock(ip);
    }

    private executeIptablesBlock(ip: string): void {
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

    // ── Unblocking ─────────────────────────────────────────────────

    /**
     * Unblock an IP using the same method that was used to block it.
     */
    async unblock(ip: string): Promise<boolean> {
        const record = this.activeBlocks.get(ip);
        if (!record) return false;

        const method = record.blockMethod || 'iptables'; // fallback for old records

        log(`[Blocker] 🔓 Unblocking IP: ${ip} (method: ${method})`);

        if (!this._dryRun) {
            // Undo primary method
            switch (method) {
                case 'cloudflare_api': {
                    if (this.cfBlocker) {
                        await this.cfBlocker.unblockIP(ip);
                    }
                    break;
                }

                case 'nginx_deny':
                case 'apache_deny': {
                    if (this.webDenyManager) {
                        await this.webDenyManager.removeDeny(ip);
                    }
                    break;
                }
            }

            // Always remove iptables too (was always added alongside)
            // Use a while loop to handle duplicate rules that might have been added due to race conditions
            const iptablesCmd = `while sudo iptables -D INPUT -s ${ip} -j DROP 2>/dev/null; do :; done; while sudo iptables -D DOCKER-USER -s ${ip} -j DROP 2>/dev/null; do :; done`;
            exec(iptablesCmd, (error: Error | null) => {
                if (error && !error.message.includes('No chain/target/match by that name')) {
                    log(`[Blocker] ⚠️ iptables unblock note for ${ip}: ${error.message}`);
                }
            });
        } else {
            log(`[Blocker] 🔶 DRY RUN: Would unblock ${ip} via ${method} — skipping`);
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
                    const blockRecord = record as BlockRecord;
                    // Backfill blockMethod for old records
                    if (!blockRecord.blockMethod) {
                        blockRecord.blockMethod = 'iptables';
                    }
                    // Promote expired temp blocks to perm (survived a restart = keep blocked)
                    if (blockRecord.expiresAt && blockRecord.expiresAt < Date.now()) {
                        log(`[Blocker] ⬆️ Promoting expired temp block ${ip} → permanent (survived restart)`);
                        blockRecord.action = 'perm_block';
                        blockRecord.expiresAt = null;
                    }
                    this.activeBlocks.set(ip, blockRecord);
                    if (!this._dryRun) {
                        this.executeBlock(ip, blockRecord.blockMethod, blockRecord.reason, blockRecord);
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
