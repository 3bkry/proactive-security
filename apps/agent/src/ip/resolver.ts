/**
 * Real-IP Resolver
 * Extracts the true client IP from log lines, only trusting proxy headers
 * when the request originates from a validated proxy range.
 */

import { isCloudflareIP } from './cloudflare.js';
import { isInAnyRange, parseCIDR, type ParsedCIDR } from './cidr.js';

export interface ResolvedIP {
    realIP: string;
    proxyIP: string | null;
    method: 'cf-connecting-ip' | 'x-forwarded-for' | 'x-real-ip' | 'remote_addr';
}

// User-configurable additional trusted proxies (e.g. local load balancers)
let trustedProxyRanges: ParsedCIDR[] = [];

export function setTrustedProxies(cidrs: string[]): void {
    trustedProxyRanges = [];
    for (const cidr of cidrs) {
        const parsed = parseCIDR(cidr);
        if (parsed) trustedProxyRanges.push(parsed);
    }
}

/** Check if an IP is a trusted proxy (Cloudflare or user-configured) */
function isTrustedProxy(ip: string): boolean {
    return isCloudflareIP(ip) || isInAnyRange(ip, trustedProxyRanges);
}

// ── Header extraction patterns ──────────────────────────────────────
const CF_CONNECTING_IP = /CF-Connecting-IP[:\s]+["']?(\d{1,3}(?:\.\d{1,3}){3})\b/i;
const X_FORWARDED_FOR = /X-Forwarded-For[:\s]+["']?(\d{1,3}(?:\.\d{1,3}){3})\b/i;
const X_REAL_IP = /X-Real-IP[:\s]+["']?(\d{1,3}(?:\.\d{1,3}){3})\b/i;

// Generic: extract ALL IPs from the line
const ALL_IPS = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g;

/**
 * Resolve the real client IP from a raw log line.
 *
 * Strategy:
 * 1. Extract all IPs from the line
 * 2. Identify the "remote_addr" (typically the FIRST IP in Nginx/Apache combined format)
 * 3. If remote_addr is a trusted proxy → trust headers in priority order
 * 4. If remote_addr is NOT a trusted proxy → ignore all headers, use remote_addr
 */
export function resolveRealIP(logLine: string): ResolvedIP | null {
    const allIPs: string[] = [];
    let match: RegExpExecArray | null;
    const ipRegex = new RegExp(ALL_IPS);
    while ((match = ipRegex.exec(logLine)) !== null) {
        allIPs.push(match[1]);
    }

    if (allIPs.length === 0) return null;

    // In standard log formats, the first IP is typically the remote_addr
    const remoteAddr = allIPs[0];

    // If the remote_addr is a trusted proxy, extract the real IP from headers
    if (isTrustedProxy(remoteAddr)) {
        // Priority 1: CF-Connecting-IP
        const cfMatch = logLine.match(CF_CONNECTING_IP);
        if (cfMatch) {
            return { realIP: cfMatch[1], proxyIP: remoteAddr, method: 'cf-connecting-ip' };
        }

        // Priority 2: X-Forwarded-For (first IP in the chain)
        const xffMatch = logLine.match(X_FORWARDED_FOR);
        if (xffMatch) {
            return { realIP: xffMatch[1], proxyIP: remoteAddr, method: 'x-forwarded-for' };
        }

        // Priority 3: X-Real-IP
        const xriMatch = logLine.match(X_REAL_IP);
        if (xriMatch) {
            return { realIP: xriMatch[1], proxyIP: remoteAddr, method: 'x-real-ip' };
        }

        // Proxy IP but no forwarding headers found — still use first non-proxy IP if available
        for (const ip of allIPs) {
            if (!isTrustedProxy(ip)) {
                return { realIP: ip, proxyIP: remoteAddr, method: 'remote_addr' };
            }
        }

        // All IPs are proxies (edge case) — use remote_addr as fallback
        return { realIP: remoteAddr, proxyIP: null, method: 'remote_addr' };
    }

    // Remote_addr is NOT a trusted proxy → ignore all forwarding headers (spoofable)
    return { realIP: remoteAddr, proxyIP: null, method: 'remote_addr' };
}

/**
 * Quick IP extraction for non-HTTP logs (auth.log, syslog, etc.)
 * where proxy headers are never present.
 */
export function extractSimpleIP(logLine: string): string | null {
    const match = logLine.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
    return match ? match[1] : null;
}
