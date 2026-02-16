/**
 * Cloudflare IP Range Manager
 * Downloads, caches, and validates Cloudflare proxy IP ranges.
 */

import * as fs from 'fs';
import * as https from 'https';
import { log, SENTINEL_DATA_DIR } from '@sentinel/core';
import * as path from 'path';
import { parseCIDR, isInAnyRange, type ParsedCIDR } from './cidr.js';

const CF_IPV4_URL = 'https://www.cloudflare.com/ips-v4';
const CF_IPV6_URL = 'https://www.cloudflare.com/ips-v6';
const RANGES_FILE = path.join(SENTINEL_DATA_DIR, 'cloudflare_ranges.json');
const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
const STALE_THRESHOLD_MS = 48 * 60 * 60 * 1000; // consider stale after 48h

interface StoredRanges {
    v4: string[];
    v6: string[];
    lastUpdated: number;
}

let parsedRanges: ParsedCIDR[] = [];
let rawStored: StoredRanges | null = null;
let refreshTimer: ReturnType<typeof setInterval> | null = null;

/** Simple HTTPS GET → text */
function httpGet(url: string): Promise<string> {
    return new Promise((resolve, reject) => {
        https.get(url, { timeout: 10000 }, (res) => {
            if (res.statusCode !== 200) {
                reject(new Error(`HTTP ${res.statusCode} from ${url}`));
                res.resume();
                return;
            }
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => resolve(data));
        }).on('error', reject);
    });
}

/** Download fresh CF ranges and persist to disk */
async function downloadRanges(): Promise<StoredRanges> {
    log('[Cloudflare] Downloading IP ranges...');
    const [v4Text, v6Text] = await Promise.all([
        httpGet(CF_IPV4_URL),
        httpGet(CF_IPV6_URL),
    ]);

    const v4 = v4Text.trim().split('\n').filter(l => l.trim());
    const v6 = v6Text.trim().split('\n').filter(l => l.trim());

    const stored: StoredRanges = { v4, v6, lastUpdated: Date.now() };

    try {
        const dir = path.dirname(RANGES_FILE);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(RANGES_FILE, JSON.stringify(stored, null, 2));
    } catch (e) {
        log(`[Cloudflare] ⚠️ Failed to persist ranges: ${e}`);
    }

    log(`[Cloudflare] ✅ Loaded ${v4.length} IPv4 + ${v6.length} IPv6 ranges.`);
    return stored;
}

/** Parse string CIDRs into efficient lookup structures */
function compileRanges(stored: StoredRanges): void {
    rawStored = stored;
    parsedRanges = [];
    for (const cidr of [...stored.v4, ...stored.v6]) {
        const parsed = parseCIDR(cidr);
        if (parsed) parsedRanges.push(parsed);
    }
}

/** Load from disk or download fresh */
export async function initCloudflareRanges(): Promise<void> {
    // Try loading from disk first
    if (fs.existsSync(RANGES_FILE)) {
        try {
            const data: StoredRanges = JSON.parse(fs.readFileSync(RANGES_FILE, 'utf-8'));
            const age = Date.now() - data.lastUpdated;

            if (age < STALE_THRESHOLD_MS) {
                compileRanges(data);
                log(`[Cloudflare] Loaded cached ranges (${parsedRanges.length} CIDRs, age: ${Math.round(age / 3600000)}h).`);

                if (age > REFRESH_INTERVAL_MS) {
                    // Refresh in background (non-blocking)
                    downloadRanges().then(compileRanges).catch(e =>
                        log(`[Cloudflare] ⚠️ Background refresh failed: ${e}`)
                    );
                }
                startAutoRefresh();
                return;
            }
        } catch (e) {
            log(`[Cloudflare] ⚠️ Failed to read cached ranges: ${e}`);
        }
    }

    // No cache or stale, download fresh
    try {
        const fresh = await downloadRanges();
        compileRanges(fresh);
    } catch (e) {
        log(`[Cloudflare] ❌ Failed to download ranges: ${e}. Using hardcoded fallback.`);
        compileRanges(HARDCODED_FALLBACK);
    }
    startAutoRefresh();
}

function startAutoRefresh(): void {
    if (refreshTimer) return;
    refreshTimer = setInterval(async () => {
        try {
            const fresh = await downloadRanges();
            compileRanges(fresh);
        } catch (e) {
            log(`[Cloudflare] ⚠️ Scheduled refresh failed: ${e}`);
        }
    }, REFRESH_INTERVAL_MS);
    // Don't keep process alive just for this timer
    if (refreshTimer && typeof refreshTimer === 'object' && 'unref' in refreshTimer) {
        refreshTimer.unref();
    }
}

/** Check if an IP belongs to Cloudflare's proxy network */
export function isCloudflareIP(ip: string): boolean {
    return isInAnyRange(ip, parsedRanges);
}

/** Get the raw CIDR strings (for installer/Nginx config injection) */
export function getCloudflareRanges(): { v4: string[]; v6: string[] } {
    return rawStored
        ? { v4: [...rawStored.v4], v6: [...rawStored.v6] }
        : { v4: [...HARDCODED_FALLBACK.v4], v6: [...HARDCODED_FALLBACK.v6] };
}

/** Hardcoded fallback — only used if network is down on first boot */
const HARDCODED_FALLBACK: StoredRanges = {
    v4: [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    ],
    v6: [
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    ],
    lastUpdated: 0,
};
