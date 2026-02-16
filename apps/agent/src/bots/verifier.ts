/**
 * Bot Verification Engine
 *
 * Verifies search engine bots using DNS round-trip:
 *  1. Reverse DNS lookup of IP → hostname
 *  2. Forward DNS resolve hostname → IP
 *  3. If round-trip matches → verified bot
 *
 * Supported bots: Googlebot, Bingbot, Yahoo (Slurp), DuckDuckBot
 *
 * All DNS calls are async (dns.promises) — never blocks main thread.
 * Results are cached with 24h TTL for performance.
 */

import * as dns from 'dns';
import { log } from '@sentinel/core';

interface CachedVerification {
    verified: boolean;
    hostname: string | null;
    expiry: number;
}

const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const cache: Map<string, CachedVerification> = new Map();

// Hostname suffixes that verify each bot
const BOT_DOMAIN_MAP: Record<string, string[]> = {
    googlebot: ['.googlebot.com', '.google.com'],
    bingbot: ['.search.msn.com'],
    slurp: ['.crawl.yahoo.net'],
    duckduckbot: ['.duckduckgo.com'],
};

/**
 * Detect which bot a User-Agent claims to be.
 * Returns null if it doesn't claim to be a known bot.
 */
function detectClaimedBot(userAgent: string): string | null {
    const ua = userAgent.toLowerCase();
    if (ua.includes('googlebot')) return 'googlebot';
    if (ua.includes('bingbot')) return 'bingbot';
    if (ua.includes('slurp')) return 'slurp';
    if (ua.includes('duckduckbot')) return 'duckduckbot';
    return null;
}

/**
 * Verify if an IP is a legitimate search engine bot.
 *
 * @param ip        - The IP address to verify
 * @param userAgent - The User-Agent string
 * @returns true if the bot is verified via DNS round-trip
 */
export async function isVerifiedBot(ip: string, userAgent: string): Promise<boolean> {
    // Check cache first
    const cached = cache.get(ip);
    if (cached && Date.now() < cached.expiry) {
        return cached.verified;
    }

    const botType = detectClaimedBot(userAgent);
    if (!botType) {
        cacheResult(ip, false, null);
        return false;
    }

    const validDomains = BOT_DOMAIN_MAP[botType];
    if (!validDomains) {
        cacheResult(ip, false, null);
        return false;
    }

    try {
        // Step 1: Reverse DNS
        const hostnames = await dns.promises.reverse(ip);
        if (!hostnames || hostnames.length === 0) {
            cacheResult(ip, false, null);
            return false;
        }

        const hostname = hostnames[0].toLowerCase();

        // Step 2: Verify hostname matches expected bot domain
        const domainMatch = validDomains.some(domain => hostname.endsWith(domain));
        if (!domainMatch) {
            log(`[BotVerifier] ❌ ${ip} claims ${botType} but rDNS → ${hostname} (not a valid domain)`);
            cacheResult(ip, false, hostname);
            return false;
        }

        // Step 3: Forward DNS to confirm round-trip
        const addresses = await dns.promises.resolve4(hostname).catch(() => [] as string[]);
        const roundTripMatch = addresses.includes(ip);

        if (roundTripMatch) {
            log(`[BotVerifier] ✅ Verified ${botType}: ${ip} → ${hostname} → ${ip}`);
            cacheResult(ip, true, hostname);
            return true;
        } else {
            // Try IPv6 if v4 didn't match
            const addresses6 = await dns.promises.resolve6(hostname).catch(() => [] as string[]);
            const v6Match = addresses6.includes(ip);

            if (v6Match) {
                log(`[BotVerifier] ✅ Verified ${botType} (IPv6): ${ip} → ${hostname} → ${ip}`);
                cacheResult(ip, true, hostname);
                return true;
            }

            log(`[BotVerifier] ❌ ${ip} claims ${botType}, rDNS → ${hostname}, but forward DNS doesn't match`);
            cacheResult(ip, false, hostname);
            return false;
        }
    } catch (e) {
        // DNS failure — don't block, but don't verify either
        cacheResult(ip, false, null);
        return false;
    }
}

function cacheResult(ip: string, verified: boolean, hostname: string | null): void {
    cache.set(ip, {
        verified,
        hostname,
        expiry: Date.now() + CACHE_TTL_MS,
    });

    // Periodic cache cleanup — prevent unbounded growth
    if (cache.size > 10000) {
        const now = Date.now();
        for (const [key, val] of cache.entries()) {
            if (now > val.expiry) cache.delete(key);
        }
    }
}

/** Get cache stats for monitoring */
export function getBotCacheStats(): { size: number; verified: number } {
    let verified = 0;
    for (const val of cache.values()) {
        if (val.verified) verified++;
    }
    return { size: cache.size, verified };
}
