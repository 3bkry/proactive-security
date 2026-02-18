/**
 * Defense Types — Shared across blocker, rate-limiter, and pipeline.
 */

/** Actions the defense system can take */
export type BlockAction = 'logged' | 'temp_block' | 'perm_block';

/** The enforcement method used to block an IP */
export type BlockMethod = 'iptables' | 'cloudflare_api' | 'nginx_deny' | 'apache_deny';

/** Full record of a defense action */
export interface BlockRecord {
    ip: string;
    realIP: string;
    proxyIP: string | null;
    userAgent: string | null;
    endpoint: string | null;
    method: string | null;
    timestamp: number;
    action: BlockAction;
    reason: string;
    risk: string;
    source: string;
    expiresAt: number | null;  // null = permanent
    blockMethod: BlockMethod;
    cfRuleId?: string;         // Cloudflare rule ID for efficient unblock
}

/** Internal offense tracker entry */
export interface OffenseEntry {
    count: number;
    firstSeen: number;
    lastSeen: number;
    actions: BlockAction[];
}

/** Rate-limiter verdict */
export interface RateLimitVerdict {
    triggered: boolean;
    reason: string | null;
    metric: 'request_rate' | 'endpoint_scan' | 'error_rate' | null;
    value: number;
    threshold: number;
}

/** Configurable defense thresholds */
export interface DefenseConfig {
    // Progressive blocking
    tempBlockDurationMin: number;   // default: 15
    tempBlockDurationMax: number;   // default: 30
    offenseWindowSec: number;       // default: 60
    permBlockAfterTempBlocks: number; // default: 3 temp blocks → perm

    // Rate limiting
    rateLimit_requestsPerSec: number;  // default: 50
    rateLimit_uniqueEndpoints: number; // in rateLimitWindowSec
    rateLimit_errorRatePercent: number; // default: 80 (%)
    rateLimit_windowSec: number;       // default: 30

    // Whitelist
    whitelistIPs: string[];
    trustedProxyCIDRs: string[];
}

export const DEFAULT_DEFENSE_CONFIG: DefenseConfig = {
    tempBlockDurationMin: 10,
    tempBlockDurationMax: 30,
    offenseWindowSec: 60,
    permBlockAfterTempBlocks: 3,

    rateLimit_requestsPerSec: 100,
    rateLimit_uniqueEndpoints: 150,
    rateLimit_errorRatePercent: 80,
    rateLimit_windowSec: 30,

    whitelistIPs: [],
    trustedProxyCIDRs: [],
};
