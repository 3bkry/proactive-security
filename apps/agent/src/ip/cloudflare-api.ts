/**
 * Cloudflare API Client — Block/Unblock IPs via CF Access Rules
 *
 * Supports two authentication methods:
 *  1. Global API Key + Email (simpler — auto-discovers zones)
 *  2. API Token + Zone ID (scoped, recommended for production)
 *
 * With Global API Key, the agent calls GET /zones to discover all zone IDs
 * automatically, so the user only needs to provide their key and email.
 */

import * as https from 'https';
import { log } from '@sentinel/core';

export interface CloudflareAPIConfig {
    // Option 1: Global API Key (simpler setup — no zone ID needed)
    apiKey?: string;
    email?: string;
    // Option 2: API Token (scoped, requires zone ID)
    apiToken?: string;
    zoneId?: string;
}

interface CFAPIResponse {
    success: boolean;
    errors: Array<{ code: number; message: string }>;
    result: any;
    result_info?: { page: number; total_pages: number };
}

export class CloudflareBlocker {
    private authHeaders: Record<string, string>;
    private zoneIds: string[] = [];
    private ruleCache: Map<string, string> = new Map(); // ip → ruleId
    private ready: Promise<void>;

    // Rate limit protection: serial queue with delay between requests
    private requestQueue: Promise<any> = Promise.resolve();
    private static readonly REQUEST_DELAY_MS = 250; // 250ms between calls = max ~240 req/min (CF allows 1200/5min)

    constructor(config: CloudflareAPIConfig) {
        // Determine auth method
        if (config.apiKey && config.email) {
            this.authHeaders = {
                'X-Auth-Key': config.apiKey,
                'X-Auth-Email': config.email,
                'Content-Type': 'application/json',
            };
            if (config.zoneId) {
                this.zoneIds = [config.zoneId];
            }
            log('[CF-API] Using Global API Key authentication.');
        } else if (config.apiToken) {
            this.authHeaders = {
                'Authorization': `Bearer ${config.apiToken}`,
                'Content-Type': 'application/json',
            };
            if (config.zoneId) {
                this.zoneIds = [config.zoneId];
            }
            log('[CF-API] Using API Token authentication.');
        } else {
            this.authHeaders = {};
            log('[CF-API] ❌ No valid credentials provided.');
        }

        // Auto-discover zones if none provided
        this.ready = this.init();
    }

    private async init(): Promise<void> {
        if (this.zoneIds.length === 0) {
            await this.discoverZones();
        }
        if (this.zoneIds.length > 0) {
            log(`[CF-API] ✅ Ready. Managing ${this.zoneIds.length} zone(s).`);
        } else {
            log('[CF-API] ❌ No zones found. Cloudflare API blocking will not work.');
        }
    }

    /**
     * Auto-discover all zones accessible with the current credentials.
     */
    private async discoverZones(): Promise<void> {
        try {
            log('[CF-API] Auto-discovering zones...');
            const response = await this.apiRequest('GET', '/zones?per_page=50&status=active');

            if (response.success && response.result?.length > 0) {
                this.zoneIds = response.result.map((z: any) => z.id);
                const names = response.result.map((z: any) => z.name).join(', ');
                log(`[CF-API] Found ${this.zoneIds.length} zone(s): ${names}`);
            } else {
                log(`[CF-API] ⚠️ No zones found: ${JSON.stringify(response.errors || [])}`);
            }
        } catch (e) {
            log(`[CF-API] ❌ Zone discovery failed: ${e}`);
        }
    }

    /**
     * Block an IP via Cloudflare Access Rules.
     * Creates the rule on ALL zones — an attacker on one domain is a threat to all.
     */
    async blockIP(ip: string, reason: string): Promise<string | null> {
        await this.ready;
        if (this.zoneIds.length === 0) return null;

        let firstRuleId: string | null = null;

        try {
            const body = JSON.stringify({
                mode: 'block',
                configuration: { target: 'ip', value: ip },
                notes: `SentinelAI: ${reason} (${new Date().toISOString()})`,
            });

            for (const zoneId of this.zoneIds) {
                const response = await this.throttledRequest('POST', `/zones/${zoneId}/firewall/access_rules/rules`, body);

                if (response.success && response.result?.id) {
                    if (!firstRuleId) firstRuleId = response.result.id;
                } else if (response.errors?.some((e: any) => e.message?.includes('already exists'))) {
                    if (!firstRuleId) firstRuleId = 'existing';
                }
            }

            if (firstRuleId) {
                this.ruleCache.set(ip, firstRuleId);
                log(`[CF-API] ✅ Blocked ${ip} across ${this.zoneIds.length} zone(s)`);
            } else {
                log(`[CF-API] ❌ Failed to block ${ip} on any zone`);
            }

            return firstRuleId;
        } catch (e) {
            log(`[CF-API] ❌ Error blocking ${ip}: ${e}`);
            return firstRuleId;
        }
    }

    /**
     * Unblock an IP by finding and deleting its access rule.
     */
    async unblockIP(ip: string): Promise<boolean> {
        await this.ready;
        if (this.zoneIds.length === 0) return false;

        let unblocked = false;

        try {
            for (const zoneId of this.zoneIds) {
                let ruleId: string | undefined;
                try {
                    const response = await this.throttledRequest(
                        'GET',
                        `/zones/${zoneId}/firewall/access_rules/rules?configuration.value=${ip}&mode=block&page=1&per_page=5`
                    );
                    if (response.success && response.result?.length > 0) {
                        ruleId = response.result[0].id;
                    }
                } catch { /* skip zone */ }

                if (!ruleId) continue;

                const delResponse = await this.throttledRequest(
                    'DELETE',
                    `/zones/${zoneId}/firewall/access_rules/rules/${ruleId}`
                );
                if (delResponse.success) unblocked = true;
            }

            if (unblocked) {
                this.ruleCache.delete(ip);
                log(`[CF-API] ✅ Unblocked ${ip} from all zones`);
            } else {
                log(`[CF-API] ℹ️ No block rule found for ${ip} in any zone`);
            }

            return unblocked;
        } catch (e) {
            log(`[CF-API] ❌ Error unblocking ${ip}: ${e}`);
            return unblocked;
        }
    }

    async listBlocked(): Promise<Array<{ ip: string; ruleId: string; notes: string }>> {
        await this.ready;
        if (this.zoneIds.length === 0) return [];

        const blocked: Array<{ ip: string; ruleId: string; notes: string }> = [];
        const zoneId = this.zoneIds[0];
        let page = 1;

        try {
            while (page <= 10) {
                const response = await this.apiRequest(
                    'GET',
                    `/zones/${zoneId}/firewall/access_rules/rules?mode=block&page=${page}&per_page=50`
                );
                if (!response.success || !response.result?.length) break;

                for (const rule of response.result) {
                    if (rule.configuration?.target === 'ip') {
                        blocked.push({ ip: rule.configuration.value, ruleId: rule.id, notes: rule.notes || '' });
                        this.ruleCache.set(rule.configuration.value, rule.id);
                    }
                }
                if (!response.result_info || page >= response.result_info.total_pages) break;
                page++;
            }
        } catch (e) {
            log(`[CF-API] ⚠️ Error listing blocked IPs: ${e}`);
        }
        return blocked;
    }

    async testConnection(): Promise<boolean> {
        await this.ready;
        return this.zoneIds.length > 0;
    }

    // ── Rate-Limited Request Queue ────────────────────────────────

    /**
     * Enqueue a CF API request. All calls go through a serial queue
     * with a delay between requests to stay well under CF's rate limit.
     */
    private throttledRequest(method: string, path: string, body?: string): Promise<CFAPIResponse> {
        const task = this.requestQueue.then(async () => {
            const result = await this.apiRequest(method, path, body);
            await new Promise(r => setTimeout(r, CloudflareBlocker.REQUEST_DELAY_MS));
            return result;
        });
        // Update queue head (ignore errors so queue doesn't stall)
        this.requestQueue = task.catch(() => { });
        return task;
    }

    // ── HTTP Helper ──────────────────────────────────────────────

    private apiRequest(method: string, path: string, body?: string): Promise<CFAPIResponse> {
        return new Promise((resolve, reject) => {
            const options: https.RequestOptions = {
                hostname: 'api.cloudflare.com',
                port: 443,
                path: `/client/v4${path}`,
                method,
                headers: { ...this.authHeaders },
                timeout: 15000,
            };

            if (body) {
                (options.headers as Record<string, string | number>)['Content-Length'] = Buffer.byteLength(body);
            }

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => { data += chunk; });
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch (e) {
                        reject(new Error(`Invalid JSON response: ${data.substring(0, 200)}`));
                    }
                });
            });

            req.on('error', reject);
            req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });

            if (body) req.write(body);
            req.end();
        });
    }
}
