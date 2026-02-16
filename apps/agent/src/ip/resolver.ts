/**
 * Real-IP Resolver
 * Extracts the true client IP from log lines, only trusting proxy headers
 * when the request originates from a validated proxy range.
 *
 * Handles multiple Nginx/Apache log formats:
 *   - Standard combined:  172.68.x.x - - [...] "GET ..." 200 ... "ua"
 *   - With CF-IP field:   172.68.x.x - - [...] "GET ..." 200 ... "ua" "156.197.x.x"
 *   - Sentinel format:    172.68.x.x - 156.197.x.x - [...] "GET ..." 200 ... "ua" "cf-ip" "xff"
 *   - Raw headers:        ... CF-Connecting-IP: 156.197.x.x ...
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

/** Check if an IP looks like a valid public IP (not status code, port, etc.) */
function isValidPublicIP(ip: string): boolean {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    const nums = parts.map(Number);
    for (const n of nums) {
        if (n < 0 || n > 255 || isNaN(n)) return false;
    }
    // Filter out loopback, broadcast, zeroes
    if (nums[0] === 0 || nums[0] === 127 || nums[0] === 255) return false;
    return true;
}

// ── Header extraction patterns (for raw header logs) ────────────────
const CF_CONNECTING_IP = /CF-Connecting-IP[:\s]+["']?(\d{1,3}(?:\.\d{1,3}){3})\b/i;
const X_FORWARDED_FOR = /X-Forwarded-For[:\s]+["']?(\d{1,3}(?:\.\d{1,3}){3})\b/i;
const X_REAL_IP = /X-Real-IP[:\s]+["']?(\d{1,3}(?:\.\d{1,3}){3})\b/i;

// Generic: extract ALL IPs from the line
const ALL_IPS = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g;

// Matches quoted IPs like "156.197.153.173" — used in Nginx custom log formats
// where CF-Connecting-IP / X-Forwarded-For are logged as extra quoted fields
const QUOTED_IP = /"(\d{1,3}(?:\.\d{1,3}){3})"/g;

/**
 * Resolve the real client IP from a raw log line.
 *
 * Strategy:
 * 1. Extract the remote_addr (first IP in Nginx/Apache combined format)
 * 2. If remote_addr is a trusted proxy:
 *    a. Look for explicit header names (CF-Connecting-IP:, X-Forwarded-For:)
 *    b. Look for quoted IPs after the user-agent string (Nginx custom log
 *       formats log $http_cf_connecting_ip as extra "1.2.3.4" fields)
 *    c. Fall back to any non-proxy IP found anywhere in the line
 * 3. If remote_addr is NOT a trusted proxy → use it directly
 */
export function resolveRealIP(logLine: string): ResolvedIP | null {
    const allIPs: string[] = [];
    let match: RegExpExecArray | null;
    const ipRegex = new RegExp(ALL_IPS);
    while ((match = ipRegex.exec(logLine)) !== null) {
        if (isValidPublicIP(match[1])) {
            allIPs.push(match[1]);
        }
    }

    if (allIPs.length === 0) return null;

    // In standard log formats, the first IP is the remote_addr
    const remoteAddr = allIPs[0];

    // If the remote_addr is a trusted proxy, extract the real IP from headers
    if (isTrustedProxy(remoteAddr)) {

        // Priority 1: Explicit CF-Connecting-IP header (raw header logs)
        const cfMatch = logLine.match(CF_CONNECTING_IP);
        if (cfMatch && isValidPublicIP(cfMatch[1])) {
            return { realIP: cfMatch[1], proxyIP: remoteAddr, method: 'cf-connecting-ip' };
        }

        // Priority 2: Explicit X-Forwarded-For header
        const xffMatch = logLine.match(X_FORWARDED_FOR);
        if (xffMatch && isValidPublicIP(xffMatch[1])) {
            return { realIP: xffMatch[1], proxyIP: remoteAddr, method: 'x-forwarded-for' };
        }

        // Priority 3: Explicit X-Real-IP header
        const xriMatch = logLine.match(X_REAL_IP);
        if (xriMatch && isValidPublicIP(xriMatch[1])) {
            return { realIP: xriMatch[1], proxyIP: remoteAddr, method: 'x-real-ip' };
        }

        // Priority 4: Quoted IP fields — Nginx custom log formats
        // Real-world format:
        //   172.68.234.32 - - [...] "POST ..." 200 28 "referer" "user-agent" "156.197.153.173"
        // The last quoted IP field(s) are typically $http_cf_connecting_ip / $http_x_forwarded_for
        const quotedIPs: string[] = [];
        const quotedRegex = new RegExp(QUOTED_IP);
        let qm: RegExpExecArray | null;
        while ((qm = quotedRegex.exec(logLine)) !== null) {
            if (isValidPublicIP(qm[1])) {
                quotedIPs.push(qm[1]);
            }
        }

        // Scan from the end — the last quoted IP is most likely the CF-Connecting-IP
        for (let i = quotedIPs.length - 1; i >= 0; i--) {
            const ip = quotedIPs[i];
            if (!isTrustedProxy(ip)) {
                return { realIP: ip, proxyIP: remoteAddr, method: 'cf-connecting-ip' };
            }
        }

        // Priority 5: Any non-proxy IP anywhere in the line
        for (const ip of allIPs) {
            if (ip !== remoteAddr && !isTrustedProxy(ip)) {
                return { realIP: ip, proxyIP: remoteAddr, method: 'remote_addr' };
            }
        }

        // All IPs are proxies — fallback to remote_addr
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
    return match && isValidPublicIP(match[1]) ? match[1] : null;
}
