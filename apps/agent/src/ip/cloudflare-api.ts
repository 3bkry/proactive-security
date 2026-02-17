/**
 * Cloudflare API Client — Block/Unblock IPs via CF Access Rules
 *
 * Uses the Cloudflare API v4 to create/delete IP access rules.
 * This is the preferred blocking method when the server is behind Cloudflare,
 * as iptables cannot block real client IPs (packets come from CF proxy IPs).
 *
 * Requires: CF_API_TOKEN + CF_ZONE_ID in config.
 */

import * as https from 'https';
import { log } from '@sentinel/core';

export interface CloudflareAPIConfig {
    apiToken: string;
    zoneId: string;
}

interface CFAccessRule {
    id: string;
    mode: string;
    notes: string;
    configuration: {
        target: string;
        value: string;
    };
}

interface CFAPIResponse {
    success: boolean;
    errors: Array<{ code: number; message: string }>;
    result: any;
    result_info?: { page: number; total_pages: number };
}

export class CloudflareBlocker {
    private apiToken: string;
    private zoneId: string;
    // Cache of ruleId → IP for fast unblock
    private ruleCache: Map<string, string> = new Map(); // ip → ruleId

    constructor(config: CloudflareAPIConfig) {
        this.apiToken = config.apiToken;
        this.zoneId = config.zoneId;
        log('[CF-API] Cloudflare API blocking initialized.');
    }

    /**
     * Block an IP via Cloudflare Access Rules.
     * Returns the rule ID on success, or null on failure.
     */
    async blockIP(ip: string, reason: string): Promise<string | null> {
        try {
            const body = JSON.stringify({
                mode: 'block',
                configuration: {
                    target: 'ip',
                    value: ip,
                },
                notes: `SentinelAI: ${reason} (${new Date().toISOString()})`,
            });

            const response = await this.apiRequest('POST', `/zones/${this.zoneId}/firewall/access_rules/rules`, body);

            if (response.success && response.result?.id) {
                const ruleId = response.result.id;
                this.ruleCache.set(ip, ruleId);
                log(`[CF-API] ✅ Blocked ${ip} via Cloudflare (rule: ${ruleId})`);
                return ruleId;
            }

            // Check if already blocked
            if (response.errors?.some((e: any) => e.message?.includes('already exists'))) {
                log(`[CF-API] ℹ️ ${ip} is already blocked in Cloudflare.`);
                return 'existing';
            }

            log(`[CF-API] ❌ Failed to block ${ip}: ${JSON.stringify(response.errors)}`);
            return null;
        } catch (e) {
            log(`[CF-API] ❌ Error blocking ${ip}: ${e}`);
            return null;
        }
    }

    /**
     * Unblock an IP by finding and deleting its access rule.
     */
    async unblockIP(ip: string): Promise<boolean> {
        try {
            // Try cached rule ID first
            let ruleId = this.ruleCache.get(ip);

            if (!ruleId || ruleId === 'existing') {
                // Search for the rule
                const foundId = await this.findRuleByIP(ip);
                if (!foundId) {
                    log(`[CF-API] ℹ️ No block rule found for ${ip} in Cloudflare.`);
                    return false;
                }
                ruleId = foundId;
            }

            const response = await this.apiRequest(
                'DELETE',
                `/zones/${this.zoneId}/firewall/access_rules/rules/${ruleId}`
            );

            if (response.success) {
                this.ruleCache.delete(ip);
                log(`[CF-API] ✅ Unblocked ${ip} from Cloudflare (rule: ${ruleId})`);
                return true;
            }

            log(`[CF-API] ❌ Failed to unblock ${ip}: ${JSON.stringify(response.errors)}`);
            return false;
        } catch (e) {
            log(`[CF-API] ❌ Error unblocking ${ip}: ${e}`);
            return false;
        }
    }

    /**
     * Find a block rule for a specific IP.
     */
    private async findRuleByIP(ip: string): Promise<string | null> {
        try {
            const response = await this.apiRequest(
                'GET',
                `/zones/${this.zoneId}/firewall/access_rules/rules?configuration.value=${ip}&mode=block&page=1&per_page=20`
            );

            if (response.success && response.result?.length > 0) {
                return response.result[0].id;
            }
            return null;
        } catch (e) {
            log(`[CF-API] ⚠️ Error searching for rule: ${e}`);
            return null;
        }
    }

    /**
     * List all blocked IPs in Cloudflare (SentinelAI-created rules).
     */
    async listBlocked(): Promise<Array<{ ip: string; ruleId: string; notes: string }>> {
        const blocked: Array<{ ip: string; ruleId: string; notes: string }> = [];
        let page = 1;
        const maxPages = 10;

        try {
            while (page <= maxPages) {
                const response = await this.apiRequest(
                    'GET',
                    `/zones/${this.zoneId}/firewall/access_rules/rules?mode=block&page=${page}&per_page=50`
                );

                if (!response.success || !response.result?.length) break;

                for (const rule of response.result) {
                    if (rule.configuration?.target === 'ip') {
                        blocked.push({
                            ip: rule.configuration.value,
                            ruleId: rule.id,
                            notes: rule.notes || '',
                        });
                        // Update cache
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

    /**
     * Test API connectivity.
     */
    async testConnection(): Promise<boolean> {
        try {
            const response = await this.apiRequest('GET', `/zones/${this.zoneId}`);
            if (response.success) {
                log(`[CF-API] ✅ Connected to Cloudflare zone: ${response.result?.name || this.zoneId}`);
                return true;
            }
            log(`[CF-API] ❌ Connection test failed: ${JSON.stringify(response.errors)}`);
            return false;
        } catch (e) {
            log(`[CF-API] ❌ Connection test error: ${e}`);
            return false;
        }
    }

    // ── HTTP Request Helper ──────────────────────────────────────────

    private apiRequest(method: string, path: string, body?: string): Promise<CFAPIResponse> {
        return new Promise((resolve, reject) => {
            const options: https.RequestOptions = {
                hostname: 'api.cloudflare.com',
                port: 443,
                path: `/client/v4${path}`,
                method,
                headers: {
                    'Authorization': `Bearer ${this.apiToken}`,
                    'Content-Type': 'application/json',
                },
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
