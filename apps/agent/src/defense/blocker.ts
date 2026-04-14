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
import { SentinelDB } from '../../../../packages/core/src/db.js';

const WHITELIST_FILE = process.env.SENTINEL_CONFIG_DIR ? path.join(process.env.SENTINEL_CONFIG_DIR, 'whitelist.json') : '/etc/sentinel/whitelist.json';

export interface BlockerConfig {
    defense?: Partial<DefenseConfig>;
    dryRun?: boolean;
    cloudflareAPI?: CloudflareAPIConfig;
    db?: SentinelDB; // Add db to BlockerConfig
}

export class Blocker {
    private offenses: Map<string, OffenseEntry> = new Map();
    private activeBlocks: Map<string, BlockRecord> = new Map();
    private tempBlockCounts: Map<string, number> = new Map();
    private config: DefenseConfig;
    private whitelistIPs: Set<string>;
    private _dryRun: boolean = false;
    private db?: SentinelDB; // Add db property

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
            this.db = bc.db; // Initialize db from BlockerConfig
        } else {
            // Old format: (DefenseConfig, dryRun)
            defenseConfig = (configOrDefense as Partial<DefenseConfig>) || {};
            this._dryRun = dryRun || false;
            // db is not passed in old format, will be undefined
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
        this.loadSafeKeywords();

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
        // If currently blocked, unblock first
        if (this.activeBlocks.has(ip)) {
            this.unblock(ip);
        }
        // Add explicit iptables ACCEPT rule so this IP is always allowed
        if (!this._dryRun) {
            this.executeIptablesAllow(ip);
        }
        log(`[Blocker] ✅ Added ${ip} to whitelist + iptables ACCEPT.`);
        return true;
    }

    removeFromWhitelist(ip: string): boolean {
        if (!this.whitelistIPs.has(ip)) return false;
        this.whitelistIPs.delete(ip);
        this.config.whitelistIPs = [...this.whitelistIPs];
        this.persistWhitelist();
        // Remove the iptables ACCEPT rule
        if (!this._dryRun) {
            this.removeIptablesAllow(ip);
        }
        log(`[Blocker] 🗑️ Removed ${ip} from whitelist + iptables ACCEPT.`);
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
            // Use WHITELIST_FILE instead of CONFIG_FILE for whitelist persistence
            const dir = path.dirname(WHITELIST_FILE);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(WHITELIST_FILE, JSON.stringify(this.config.whitelistIPs, null, 2));
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
        const isManual = params.source === 'telegram';

        // ── Safety Checks ──
        if (await this.isSafe(realIP, params.userAgent, isManual)) return null;

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
            this.saveState(record); // Save individual record
        }

        return { action, record };
    }

    private randomTempBlockDuration(): number {
        const min = this.config.tempBlockDurationMin * 60 * 1000;
        const max = this.config.tempBlockDurationMax * 60 * 1000;
        return Math.floor(Math.random() * (max - min)) + min;
    }

    // ── Known Service IP Ranges (Never Ban) ─────────────────────────
    // These are webhook/monitoring services that connect TO your server.
    // Banning them breaks your own integrations.
    private static readonly SAFE_SERVICE_CIDRS: string[] = [
        // Telegram Bot API — webhook callbacks
        '149.154.160.0/20',
        '91.108.4.0/22',
        '91.108.8.0/22',
        '91.108.12.0/22',
        '91.108.16.0/22',
        '91.108.20.0/22',
        '91.108.56.0/22',
        // UptimeRobot monitoring
        '216.144.250.0/24',
        '69.162.124.0/24',
        // Internal/private ranges (Docker, LAN)
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
    ];

    /**
     * Lightweight CIDR match: check if an IPv4 address falls within a CIDR range.
     */
    private static ipInCIDR(ip: string, cidr: string): boolean {
        const [rangeIP, prefixStr] = cidr.split('/');
        const prefix = parseInt(prefixStr, 10);
        if (isNaN(prefix)) return false;

        const ipNum = Blocker.ipToNumber(ip);
        const rangeNum = Blocker.ipToNumber(rangeIP);
        if (ipNum === null || rangeNum === null) return false;

        const mask = ~((1 << (32 - prefix)) - 1) >>> 0;
        return (ipNum & mask) === (rangeNum & mask);
    }

    private static ipToNumber(ip: string): number | null {
        const parts = ip.split('.');
        if (parts.length !== 4) return null;
        let num = 0;
        for (const part of parts) {
            const octet = parseInt(part, 10);
            if (isNaN(octet) || octet < 0 || octet > 255) return null;
            num = (num << 8) | octet;
        }
        return num >>> 0;
    }

    // ── Safety Checks ──────────────────────────────────────────────

    private async isSafe(ip: string, userAgent: string | null, isManual: boolean = false): Promise<boolean> {
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

        // Known service IP ranges (Telegram, UptimeRobot, private networks)
        for (const cidr of Blocker.SAFE_SERVICE_CIDRS) {
            if (Blocker.ipInCIDR(ip, cidr)) {
                log(`[Blocker] 🛡️ SAFETY: Skipping known service IP ${ip} (range: ${cidr})`);
                return true;
            }
        }

        // Bypass remaining checks if triggered manually
        if (isManual) return false;

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

        // Final deep check: Whois lookup to catch out-of-date CF ranges or unverified Google IPs
        if (await this.isSafeWhois(ip)) {
            return true;
        }

        return false;
    }

    /**
     * Hardcoded baseline — these are never removed. CDN/Cloud only.
     * Everything else is managed dynamically via Telegram /safelist command.
     */
    private static readonly WHOIS_BASELINE_KEYWORDS: string[] = [
        'cloudflare',
        'google',
        'microsoft',
        'amazon',
        'akamai',
    ];

    /** Dynamic user-managed keywords — persisted to disk */
    private dynamicSafeKeywords: string[] = [];
    private static readonly SAFE_ISP_FILE = path.join(SENTINEL_DATA_DIR, 'safe_isps.json');

    /** Load dynamic keywords from disk on startup */
    private loadSafeKeywords(): void {
        try {
            if (fs.existsSync(Blocker.SAFE_ISP_FILE)) {
                const data = JSON.parse(fs.readFileSync(Blocker.SAFE_ISP_FILE, 'utf-8'));
                if (Array.isArray(data)) {
                    this.dynamicSafeKeywords = data.map((k: string) => k.toLowerCase().trim());
                    log(`[Blocker] Loaded ${this.dynamicSafeKeywords.length} custom safe ISP keywords.`);
                }
            }
        } catch (e) {
            log(`[Blocker] ⚠️ Failed to load safe ISP keywords: ${e}`);
        }
    }

    /** Persist dynamic keywords to disk */
    private persistSafeKeywords(): void {
        try {
            const dir = path.dirname(Blocker.SAFE_ISP_FILE);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(Blocker.SAFE_ISP_FILE, JSON.stringify(this.dynamicSafeKeywords, null, 2));
        } catch (e) {
            log(`[Blocker] ⚠️ Failed to persist safe ISP keywords: ${e}`);
        }
    }

    /** Get the merged list (baseline + dynamic) */
    private getAllSafeKeywords(): string[] {
        return [...Blocker.WHOIS_BASELINE_KEYWORDS, ...this.dynamicSafeKeywords];
    }

    // ── Public API for Telegram /safelist command ──

    /** Add a keyword to the dynamic safe list */
    public addSafeKeyword(keyword: string): boolean {
        const normalized = keyword.toLowerCase().trim();
        if (!normalized) return false;
        if (Blocker.WHOIS_BASELINE_KEYWORDS.includes(normalized)) return false;
        if (this.dynamicSafeKeywords.includes(normalized)) return false;
        this.dynamicSafeKeywords.push(normalized);
        this.persistSafeKeywords();
        this.whoisCache.clear();
        log(`[Blocker] ✅ Added safe ISP keyword: "${normalized}"`);
        return true;
    }

    /** Remove a keyword from the dynamic safe list */
    public removeSafeKeyword(keyword: string): boolean {
        const normalized = keyword.toLowerCase().trim();
        const idx = this.dynamicSafeKeywords.indexOf(normalized);
        if (idx === -1) return false;
        this.dynamicSafeKeywords.splice(idx, 1);
        this.persistSafeKeywords();
        this.whoisCache.clear();
        log(`[Blocker] 🗑️ Removed safe ISP keyword: "${normalized}"`);
        return true;
    }

    /** Get all safe keywords (baseline + dynamic, labelled) */
    public getSafeKeywords(): { baseline: string[]; custom: string[] } {
        return {
            baseline: [...Blocker.WHOIS_BASELINE_KEYWORDS],
            custom: [...this.dynamicSafeKeywords],
        };
    }

    /** Cache whois results for 10 minutes to avoid hammering whois servers */
    private whoisCache: Map<string, { safe: boolean; org: string; ts: number }> = new Map();
    private static readonly WHOIS_CACHE_TTL = 10 * 60 * 1000; // 10 minutes

    /**
     * Run a real-time whois lookup before applying a ban.
     * Checks against merged baseline + dynamic keywords.
     */
    private async isSafeWhois(ip: string): Promise<boolean> {
        const cached = this.whoisCache.get(ip);
        if (cached && Date.now() - cached.ts < Blocker.WHOIS_CACHE_TTL) {
            if (cached.safe) {
                log(`[Blocker] 🛡️ SAFETY (cached): ${ip} belongs to ${cached.org}. Skipping auto-ban.`);
            }
            return cached.safe;
        }

        const allKeywords = this.getAllSafeKeywords();

        return new Promise((resolve) => {
            exec(`whois ${ip}`, { timeout: 8000 }, (error, stdout) => {
                if (error) {
                    this.whoisCache.set(ip, { safe: false, org: 'unknown', ts: Date.now() });
                    resolve(false);
                    return;
                }
                const output = stdout.toLowerCase();

                for (const keyword of allKeywords) {
                    if (output.includes(keyword)) {
                        const orgMatch = stdout.match(/(?:OrgName|org-name|descr|netname):\s*(.+)/i);
                        const orgName = orgMatch ? orgMatch[1].trim() : keyword;

                        log(`[Blocker] 🛡️ SAFETY: Whois revealed "${orgName}" for ${ip}. Skipping auto-ban.`);
                        this.whoisCache.set(ip, { safe: true, org: orgName, ts: Date.now() });
                        resolve(true);
                        return;
                    }
                }

                this.whoisCache.set(ip, { safe: false, org: 'other', ts: Date.now() });
                resolve(false);
            });
        });
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

    /**
     * Add an explicit iptables ACCEPT rule for a whitelisted IP.
     * Also flushes any existing DROP rules for this IP first.
     */
    private executeIptablesAllow(ip: string): void {
        // 1. First flush any existing DROP rules for this IP
        const flushDrop = `while iptables -D INPUT -s ${ip} -j DROP 2>/dev/null; do :; done`;
        // 2. Then add ACCEPT rule (idempotent — check first)
        const allowCmd = `iptables -C INPUT -s ${ip} -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -s ${ip} -j ACCEPT`;
        // 3. Same for DOCKER-USER chain
        const dockerFlush = `while iptables -D DOCKER-USER -s ${ip} -j DROP 2>/dev/null; do :; done`;
        const dockerAllow = `iptables -C DOCKER-USER -s ${ip} -j ACCEPT 2>/dev/null || (iptables -L DOCKER-USER >/dev/null 2>&1 && iptables -I DOCKER-USER 1 -s ${ip} -j ACCEPT)`;

        exec(`${flushDrop} && ${allowCmd}`, (error: Error | null) => {
            if (error) {
                log(`[Blocker] ⚠️ Failed to add ACCEPT for ${ip}: ${error.message}`);
            } else {
                log(`[Blocker] ✅ iptables ACCEPT rule added for ${ip}`);
                exec(`${dockerFlush}; ${dockerAllow}`, () => { /* ok if docker chain missing */ });
            }
        });
    }

    /**
     * Remove the iptables ACCEPT rule when an IP is removed from whitelist.
     */
    private removeIptablesAllow(ip: string): void {
        const cmd = `iptables -D INPUT -s ${ip} -j ACCEPT 2>/dev/null`;
        const dockerCmd = `iptables -D DOCKER-USER -s ${ip} -j ACCEPT 2>/dev/null`;
        exec(`${cmd}; ${dockerCmd}`, (error: Error | null) => {
            if (!error) {
                log(`[Blocker] 🗑️ iptables ACCEPT rule removed for ${ip}`);
            }
        });
    }

    // ── Unblocking ─────────────────────────────────────────────────

    /**
     * Helper: exhaustively delete a single iptables rule until it's fully gone.
     * Handles duplicates from race conditions.
     */
    private flushIptablesRule(chain: string, ip: string): Promise<void> {
        return new Promise((resolve) => {
            // iptables -D will exit non-zero when no more rules remain — that's our stop condition
            exec(`iptables -D ${chain} -s ${ip} -j DROP`, (err) => {
                if (err) {
                    // No more rules for this IP in this chain — done
                    resolve();
                } else {
                    // Rule was deleted; try again to catch duplicates
                    this.flushIptablesRule(chain, ip).then(resolve);
                }
            });
        });
    }

    /**
     * Exhaustively remove all iptables DROP rules for an IP across INPUT and DOCKER-USER chains.
     */
    private async flushAllIptablesForIP(ip: string): Promise<void> {
        await this.flushIptablesRule('INPUT', ip);
        // DOCKER-USER may not exist — that's fine, errors are silent above
        try {
            await this.flushIptablesRule('DOCKER-USER', ip);
        } catch { /* ok if chain missing */ }
        log(`[Blocker] ✅ iptables rules flushed for ${ip}`);
    }

    /**
     * Unblock an IP using the same method that was used to block it.
     * Also works on IPs not in activeBlocks (manual unban from dashboard/Telegram).
     */
    async unblock(ip: string): Promise<boolean> {
        const record = this.activeBlocks.get(ip);
        const method = record?.blockMethod || 'iptables'; // fallback for old/manual records

        log(`[Blocker] 🔓 Unblocking IP: ${ip} (method: ${method})`);

        if (!this._dryRun) {
            // 1. Undo primary CF/web-server method
            switch (method) {
                case 'cloudflare_api': {
                    if (this.cfBlocker) {
                        const ok = await this.cfBlocker.unblockIP(ip);
                        log(`[Blocker] CF unblock for ${ip}: ${ok ? '✅ success' : '⚠️ not found or failed'}`);
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

            // 2. Always flush ALL iptables rules for this IP (handles duplicates)
            await this.flushAllIptablesForIP(ip);
        } else {
            log(`[Blocker] 🔶 DRY RUN: Would unblock ${ip} via ${method} — skipping`);
        }

        this.activeBlocks.delete(ip);
        this.offenses.delete(ip);
        this.tempBlockCounts.delete(ip);
        this.saveState(); // Save state after unblock
        log(`[Blocker] ✅ IP ${ip} fully unblocked and removed from all records.`);
        return true;
    }

    async unblockAll(): Promise<void> {
        const ips = this.getBlockedIPs();
        log(`[Blocker] 🔓 Bulk Unblock: Removing all ${ips.length} active blocks...`);
        for (const ip of ips) {
            await this.unblock(ip);
        }
        log(`[Blocker] ✅ All IPs unblocked.`);
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

    private saveState(ipRecord?: BlockRecord): void {
        if (!this.db) return;
        try {
            if (ipRecord) {
                // Upsert single record
                this.db.saveBlock({
                    ...ipRecord,
                    action: ipRecord.action || 'perm_block' // Default action if not set
                });
            } else {
                // If no specific record is passed, it means a general state change (like unblock)
                // We need to remove the record from DB if it was deleted from activeBlocks
                // Or, if this is called after a general cleanup, ensure DB reflects current activeBlocks
                // For simplicity, if no ipRecord, we assume a full sync or deletion is needed.
                // A more robust solution might involve a separate `deleteBlock` method on DB.
                // For now, we'll just ensure the DB is updated for active blocks.
                // This part needs careful consideration based on DB API.
                // Assuming `saveBlock` will update if exists, insert if new.
                // For deletions, `unblock` already handles it by not passing ipRecord.
                // If `saveState()` is called without `ipRecord` after `activeBlocks.delete(ip)`,
                // the DB should ideally also delete that record.
                // For now, we'll just ensure existing active blocks are saved.
                for (const record of this.activeBlocks.values()) {
                    this.db.saveBlock({
                        ...record,
                        action: record.action || 'perm_block'
                    });
                }
            }
        } catch (e: any) {
            log(`[Blocker] Error saving state to DB: ${e.message}`);
        }
    }

    private loadState(): void {
        this.activeBlocks.clear();
        this.tempBlockCounts.clear();

        if (this.db) {
            try {
                const activeFromDb = this.db.getActiveBlocks();
                for (const [ip, rawRecord] of Object.entries(activeFromDb)) {
                    const record = rawRecord as BlockRecord;
                    this.activeBlocks.set(ip, record);
                    // On restart, if it's in the DB and not expired, enforce the block again.
                    if (!this._dryRun) {
                        this.executeBlock(ip, record.blockMethod, record.reason, record);
                    }
                }
                log(`[Blocker] Loaded ${this.activeBlocks.size} active blocks from state.`);
            } catch (e: any) {
                log(`[Blocker] ⚠️ Failed to load state from DB: ${e.message}`);
            }
        }

        // Load whitelist from config
        try {
            if (fs.existsSync(WHITELIST_FILE)) {
                const whitelisted = JSON.parse(fs.readFileSync(WHITELIST_FILE, 'utf-8'));
                if (Array.isArray(whitelisted)) {
                    for (const ip of whitelisted) {
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
