/**
 * CIDR Matching Engine — Pure math, no I/O.
 * Supports IPv4 and IPv6.
 */

export interface ParsedCIDR {
    ip: bigint;
    mask: bigint;
    bits: number; // 32 for v4, 128 for v6
}

/** Parse an IPv4 address string to a 32-bit number */
export function ipv4ToNum(ip: string): bigint {
    const parts = ip.split('.');
    if (parts.length !== 4) return -1n;
    let num = 0n;
    for (const p of parts) {
        const n = parseInt(p, 10);
        if (isNaN(n) || n < 0 || n > 255) return -1n;
        num = (num << 8n) | BigInt(n);
    }
    return num;
}

/** Expand a (potentially abbreviated) IPv6 to 8 groups */
function expandIPv6(ip: string): string | null {
    // Handle IPv4-mapped IPv6 (::ffff:1.2.3.4)
    const v4Mapped = ip.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (v4Mapped) {
        const v4 = v4Mapped[1];
        const parts = v4.split('.').map(n => parseInt(n, 10));
        if (parts.some(n => isNaN(n) || n < 0 || n > 255)) return null;
        const hex1 = ((parts[0] << 8) | parts[1]).toString(16);
        const hex2 = ((parts[2] << 8) | parts[3]).toString(16);
        return `0000:0000:0000:0000:0000:ffff:${hex1.padStart(4, '0')}:${hex2.padStart(4, '0')}`;
    }

    let halves = ip.split('::');
    if (halves.length > 2) return null;

    if (halves.length === 2) {
        const left = halves[0] ? halves[0].split(':') : [];
        const right = halves[1] ? halves[1].split(':') : [];
        const fill = 8 - left.length - right.length;
        if (fill < 0) return null;
        const mid = Array(fill).fill('0000');
        const groups = [...left, ...mid, ...right];
        return groups.map(g => g.padStart(4, '0')).join(':');
    }

    const groups = ip.split(':');
    if (groups.length !== 8) return null;
    return groups.map(g => g.padStart(4, '0')).join(':');
}

/** Parse an IPv6 address to a 128-bit bigint */
export function ipv6ToNum(ip: string): bigint {
    const expanded = expandIPv6(ip);
    if (!expanded) return -1n;
    const groups = expanded.split(':');
    let num = 0n;
    for (const g of groups) {
        num = (num << 16n) | BigInt(parseInt(g, 16));
    }
    return num;
}

/** Detect if a string looks like IPv6 */
export function isIPv6(ip: string): boolean {
    return ip.includes(':');
}

/** Parse a CIDR string (e.g. "10.0.0.0/8" or "2400:cb00::/32") */
export function parseCIDR(cidr: string): ParsedCIDR | null {
    const [ipStr, prefixStr] = cidr.split('/');
    if (!ipStr || !prefixStr) return null;
    const prefix = parseInt(prefixStr, 10);

    if (isIPv6(ipStr)) {
        if (isNaN(prefix) || prefix < 0 || prefix > 128) return null;
        const ip = ipv6ToNum(ipStr);
        if (ip === -1n) return null;
        const mask = prefix === 0 ? 0n : ((1n << 128n) - 1n) << BigInt(128 - prefix);
        return { ip: ip & mask, mask, bits: 128 };
    } else {
        if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;
        const ip = ipv4ToNum(ipStr);
        if (ip === -1n) return null;
        const mask = prefix === 0 ? 0n : ((1n << 32n) - 1n) << BigInt(32 - prefix);
        return { ip: ip & mask, mask, bits: 32 };
    }
}

/** Check if an IP is within a parsed CIDR range */
export function isInRange(ip: string, range: ParsedCIDR): boolean {
    const v6 = isIPv6(ip);
    if (v6 && range.bits !== 128) return false;
    if (!v6 && range.bits !== 32) return false;

    const num = v6 ? ipv6ToNum(ip) : ipv4ToNum(ip);
    if (num === -1n) return false;

    return (num & range.mask) === range.ip;
}

/** Check if an IP is within any of the parsed CIDR ranges */
export function isInAnyRange(ip: string, ranges: ParsedCIDR[]): boolean {
    for (const range of ranges) {
        if (isInRange(ip, range)) return true;
    }
    return false;
}
