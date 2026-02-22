/**
 * Cloudflare API Client — Block/Unblock IPs via IP List + Custom WAF Rule
 *
 * Instead of creating individual access rules per IP, this uses a single
 * IP List ("sentinel_blocklist") + one WAF custom rule per zone that blocks
 * all IPs in the list. Much cleaner and easier to manage.
 *
 * Supports:
 *  1. Global API Key + Email (auto-discovers zones and account)
 *  2. API Token + Zone ID (scoped)
 */

import * as https from 'https';
import { log } from '@sentinel/core';

export interface CloudflareAPIConfig {
    apiKey?: string;
    email?: string;
    apiToken?: string;
    zoneId?: string;
}

interface CFAPIResponse {
    success: boolean;
    errors: Array<{ code: number; message: string }>;
    result: any;
    result_info?: { page: number; total_pages: number };
}

const LIST_NAME = 'sentinel_blocklist';
const RULE_DESCRIPTION = 'SentinelAI Auto-Block List';

export class CloudflareBlocker {
    private authHeaders: Record<string, string>;
    private zoneIds: string[] = [];
    private accountId: string = '';
    private listId: string = '';
    // item_id cache for fast removal
    private itemCache: Map<string, string> = new Map(); // ip → list_item_id
    private ready: Promise<void>;

    // Rate limit protection
    private requestQueue: Promise<any> = Promise.resolve();
    private static readonly REQUEST_DELAY_MS = 300;

    constructor(config: CloudflareAPIConfig) {
        if (config.apiKey && config.email) {
            this.authHeaders = {
                'X-Auth-Key': config.apiKey,
                'X-Auth-Email': config.email,
                'Content-Type': 'application/json',
            };
            if (config.zoneId) this.zoneIds = [config.zoneId];
            log('[CF-API] Using Global API Key authentication.');
        } else if (config.apiToken) {
            this.authHeaders = {
                'Authorization': `Bearer ${config.apiToken}`,
                'Content-Type': 'application/json',
            };
            if (config.zoneId) this.zoneIds = [config.zoneId];
            log('[CF-API] Using API Token authentication.');
        } else {
            this.authHeaders = {};
            log('[CF-API] ❌ No valid credentials provided.');
        }

        this.ready = this.init();
    }

    // ── Initialization ──────────────────────────────────────────

    private async init(): Promise<void> {
        // 1. Discover account + zones
        await this.discoverAccountAndZones();
        if (!this.accountId || this.zoneIds.length === 0) {
            log('[CF-API] ❌ Cannot initialize — no account or zones found.');
            return;
        }

        // 2. Try to find or create the IP list (non-fatal if it fails)
        await this.findOrCreateList();
        if (this.listId) {
            // 3. Load existing list items into cache
            await this.loadListItems();

            // 4. Ensure each zone has a WAF rule referencing the list
            for (const zoneId of this.zoneIds) {
                await this.ensureWAFRule(zoneId);
            }
            log(`[CF-API] ✅ Ready (IP List). ${this.itemCache.size} IPs in blocklist across ${this.zoneIds.length} zone(s).`);
        } else {
            log(`[CF-API] ⚠️ IP List unavailable — using individual access rules per zone instead.`);
            log(`[CF-API] ✅ Ready (Access Rules). ${this.zoneIds.length} zone(s).`);
        }
    }

    private async discoverAccountAndZones(): Promise<void> {
        try {
            // Get zones (also reveals account_id)
            const response = await this.throttledRequest('GET', '/zones?per_page=50&status=active');
            if (!response.success || !response.result?.length) {
                log(`[CF-API] ⚠️ No zones found: ${JSON.stringify(response.errors || [])}`);
                return;
            }

            // Account ID from first zone
            this.accountId = response.result[0].account?.id || '';
            if (!this.accountId) {
                log('[CF-API] ⚠️ Could not determine account ID from zone data.');
                return;
            }

            // Collect zone IDs (only if not pre-set)
            if (this.zoneIds.length === 0) {
                this.zoneIds = response.result.map((z: any) => z.id);
            }
            const names = response.result.map((z: any) => z.name).join(', ');
            log(`[CF-API] Account: ${this.accountId.substring(0, 8)}… | ${this.zoneIds.length} zone(s): ${names}`);
        } catch (e) {
            log(`[CF-API] ❌ Discovery failed: ${e}`);
        }
    }

    // ── IP List Management ──────────────────────────────────────

    private async findOrCreateList(): Promise<void> {
        try {
            // Try to find existing list
            const listResponse = await this.throttledRequest(
                'GET',
                `/accounts/${this.accountId}/rules/lists`
            );

            if (listResponse.success && listResponse.result) {
                const existing = listResponse.result.find((l: any) => l.name === LIST_NAME);
                if (existing) {
                    this.listId = existing.id;
                    log(`[CF-API] Found existing IP list: ${LIST_NAME} (${existing.num_items} items)`);
                    return;
                }
            }

            // Create new list
            const createResponse = await this.throttledRequest(
                'POST',
                `/accounts/${this.accountId}/rules/lists`,
                JSON.stringify({
                    name: LIST_NAME,
                    description: 'SentinelAI blocked IPs — auto-managed, do not edit manually',
                    kind: 'ip',
                })
            );

            if (createResponse.success && createResponse.result?.id) {
                this.listId = createResponse.result.id;
                log(`[CF-API] ✅ Created IP list: ${LIST_NAME}`);
            } else {
                log(`[CF-API] ❌ Failed to create IP list: ${JSON.stringify(createResponse.errors)}`);
            }
        } catch (e) {
            log(`[CF-API] ❌ List setup error: ${e}`);
        }
    }

    private async loadListItems(): Promise<void> {
        if (!this.listId) return;
        try {
            let cursor: string | undefined;
            do {
                const path = `/accounts/${this.accountId}/rules/lists/${this.listId}/items` +
                    (cursor ? `?cursor=${cursor}` : '');
                const response = await this.throttledRequest('GET', path);
                if (!response.success || !response.result) break;

                for (const item of response.result) {
                    if (item.ip) this.itemCache.set(item.ip, item.id);
                }

                cursor = (response as any).result_info?.cursors?.after;
            } while (cursor);
        } catch (e) {
            log(`[CF-API] ⚠️ Error loading list items: ${e}`);
        }
    }

    // ── WAF Custom Rule ─────────────────────────────────────────

    private async ensureWAFRule(zoneId: string): Promise<void> {
        try {
            // Get the custom firewall ruleset for this zone
            const rulesetsResponse = await this.throttledRequest(
                'GET',
                `/zones/${zoneId}/rulesets?phase=http_request_firewall_custom`
            );

            let rulesetId: string | undefined;
            let ruleExists = false;

            if (rulesetsResponse.success && rulesetsResponse.result?.length > 0) {
                rulesetId = rulesetsResponse.result[0].id;

                // Check if our rule already exists
                const rulesetDetail = await this.throttledRequest(
                    'GET',
                    `/zones/${zoneId}/rulesets/${rulesetId}`
                );

                if (rulesetDetail.success && rulesetDetail.result?.rules) {
                    ruleExists = rulesetDetail.result.rules.some(
                        (r: any) => r.description === RULE_DESCRIPTION
                    );
                }
            }

            if (ruleExists) {
                log(`[CF-API] Zone ${zoneId.substring(0, 8)}…: WAF rule already exists.`);
                return;
            }

            // Create the WAF rule that blocks IPs in our list
            const listRef = `$${LIST_NAME}`;
            const rulePayload = {
                description: RULE_DESCRIPTION,
                expression: `ip.src in ${listRef}`,
                action: 'block',
                enabled: true,
            };

            if (rulesetId) {
                // Add rule to existing ruleset
                await this.throttledRequest(
                    'POST',
                    `/zones/${zoneId}/rulesets/${rulesetId}/rules`,
                    JSON.stringify(rulePayload)
                );
            } else {
                // Create new ruleset with the rule
                await this.throttledRequest(
                    'PUT',
                    `/zones/${zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint`,
                    JSON.stringify({
                        name: 'SentinelAI Custom Rules',
                        kind: 'zone',
                        phase: 'http_request_firewall_custom',
                        rules: [rulePayload],
                    })
                );
            }

            log(`[CF-API] ✅ Zone ${zoneId.substring(0, 8)}…: WAF block rule created.`);
        } catch (e) {
            log(`[CF-API] ⚠️ Could not create WAF rule for zone ${zoneId.substring(0, 8)}…: ${e}`);
            log(`[CF-API]    (WAF Custom Rules may require a paid plan — individual access rules will be used as fallback)`);
        }
    }

    // ── Block / Unblock ─────────────────────────────────────────

    async blockIP(ip: string, reason: string): Promise<string | null> {
        await this.ready;

        // 1. Try IP List first
        if (this.listId && this.accountId) {
            const listId = await this.addToList(ip, reason);
            if (listId) return listId;
            log(`[CF-API] ⚠️ Failed to add to list, falling back to individual access rules.`);
        }

        // 2. Fallback: individual access rules
        return this.blockViaAccessRule(ip, reason);
    }

    async unblockIP(ip: string): Promise<boolean> {
        await this.ready;

        let unblocked = false;

        // 1. Try removing from IP List
        if (this.listId && this.accountId) {
            const listSuccess = await this.removeFromList(ip);
            if (listSuccess) unblocked = true;
        }

        // 2. ALWAYS try removing from Access Rules (cleanup old/fallback blocks)
        // This ensures we catch IPs that were blocked before IP Lists were active
        // or during fallback mode.
        const ruleSuccess = await this.unblockViaAccessRule(ip);
        if (ruleSuccess) unblocked = true;

        return unblocked;
    }

    // ── IP List Operations ──────────────────────────────────────

    private async addToList(ip: string, reason: string): Promise<string | null> {
        if (this.itemCache.has(ip)) {
            log(`[CF-API] ℹ️ ${ip} already in blocklist.`);
            return 'existing';
        }

        try {
            const response = await this.throttledRequest(
                'POST',
                `/accounts/${this.accountId}/rules/lists/${this.listId}/items`,
                JSON.stringify([{ ip, comment: `SentinelAI: ${reason}` }])
            );

            if (response.success) {
                // The API returns operation_id for async operations
                // Get the item ID from a follow-up query
                const itemId = response.result?.operation_id || 'pending';
                this.itemCache.set(ip, itemId);
                log(`[CF-API] ✅ Added ${ip} to blocklist (${this.itemCache.size} total)`);

                // Refresh item cache to get real IDs
                setTimeout(() => this.loadListItems(), 2000);
                return itemId;
            }

            log(`[CF-API] ❌ Failed to add ${ip} to list: ${JSON.stringify(response.errors)}`);
            return null;
        } catch (e) {
            log(`[CF-API] ❌ Error adding ${ip}: ${e}`);
            return null;
        }
    }

    private async removeFromList(ip: string): Promise<boolean> {
        const itemId = this.itemCache.get(ip);
        if (!itemId) {
            // Try refreshing cache
            await this.loadListItems();
            const freshId = this.itemCache.get(ip);
            if (!freshId) {
                log(`[CF-API] ℹ️ ${ip} not found in blocklist.`);
                return false;
            }
            return this.deleteListItem(ip, freshId);
        }

        return this.deleteListItem(ip, itemId);
    }

    private async deleteListItem(ip: string, itemId: string): Promise<boolean> {
        try {
            const response = await this.throttledRequest(
                'DELETE',
                `/accounts/${this.accountId}/rules/lists/${this.listId}/items`,
                JSON.stringify({ items: [{ id: itemId }] })
            );

            if (response.success) {
                this.itemCache.delete(ip);
                log(`[CF-API] ✅ Removed ${ip} from blocklist (${this.itemCache.size} remaining)`);
                return true;
            }

            log(`[CF-API] ❌ Failed to remove ${ip}: ${JSON.stringify(response.errors)}`);
            return false;
        } catch (e) {
            log(`[CF-API] ❌ Error removing ${ip}: ${e}`);
            return false;
        }
    }

    // ── Access Rule Fallback ────────────────────────────────────

    private async blockViaAccessRule(ip: string, reason: string): Promise<string | null> {
        if (this.zoneIds.length === 0) return null;

        let firstRuleId: string | null = null;
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
            log(`[CF-API] ✅ Blocked ${ip} via access rules across ${this.zoneIds.length} zone(s)`);
        }
        return firstRuleId;
    }

    private async unblockViaAccessRule(ip: string): Promise<boolean> {
        if (this.zoneIds.length === 0) return false;
        let unblocked = false;

        for (const zoneId of this.zoneIds) {
            try {
                const response = await this.throttledRequest(
                    'GET',
                    `/zones/${zoneId}/firewall/access_rules/rules?configuration.value=${ip}&mode=block&page=1&per_page=5`
                );
                if (response && response.success && response.result?.length > 0) {
                    const ruleId = response.result[0].id;
                    const delResponse = await this.throttledRequest(
                        'DELETE',
                        `/zones/${zoneId}/firewall/access_rules/rules/${ruleId}`
                    );
                    if (delResponse && delResponse.success) unblocked = true;
                }
            } catch (e) {
                log(`[CF-API] ⚠️ Error unblocking via access rule in zone ${zoneId.substring(0, 8)}…: ${e}`);
            }
        }

        if (unblocked) log(`[CF-API] ✅ Unblocked ${ip} via access rules`);
        return unblocked;
    }

    // ── Queries ──────────────────────────────────────────────────

    async listBlocked(): Promise<Array<{ ip: string; ruleId: string; notes: string }>> {
        await this.ready;
        const blocked: Array<{ ip: string; ruleId: string; notes: string }> = [];

        // List from IP list if available
        if (this.itemCache.size > 0) {
            for (const [ip, itemId] of this.itemCache) {
                blocked.push({ ip, ruleId: itemId, notes: 'IP List' });
            }
        }

        return blocked;
    }

    async testConnection(): Promise<boolean> {
        await this.ready;
        return this.zoneIds.length > 0;
    }

    // ── Rate-Limited Request Queue ───────────────────────────────

    private throttledRequest(method: string, path: string, body?: string): Promise<CFAPIResponse> {
        const task = this.requestQueue.then(async () => {
            const result = await this.apiRequest(method, path, body);
            await new Promise(r => setTimeout(r, CloudflareBlocker.REQUEST_DELAY_MS));
            return result;
        });
        this.requestQueue = task.catch(() => { });
        return task;
    }

    // ── HTTP Helper ──────────────────────────────────────────────

    private apiRequest(method: string, path: string, body?: string): Promise<CFAPIResponse> {
        return new Promise((resolve) => {
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
                        resolve({
                            success: false,
                            errors: [{ code: 0, message: `Invalid JSON response: ${data.substring(0, 200)}` }],
                            result: null
                        });
                    }
                });
            });

            req.on('error', (err) => {
                log(`[CF-API] ❌ Connection error (${method} ${path}): ${err.message}`);
                resolve({
                    success: false,
                    errors: [{ code: 0, message: err.message }],
                    result: null
                });
            });

            req.on('timeout', () => {
                log(`[CF-API] ❌ Request timeout (${method} ${path})`);
                req.destroy();
                resolve({
                    success: false,
                    errors: [{ code: 0, message: 'Request timeout' }],
                    result: null
                });
            });

            if (body) req.write(body);
            req.end();
        });
    }
}
