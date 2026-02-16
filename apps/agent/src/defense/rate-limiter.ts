/**
 * Sliding-Window Rate Limiter
 *
 * Detects:
 *  - High request rate (> N req/sec)
 *  - Endpoint scanning (many unique endpoints rapidly)
 *  - High error rate (> X% 404s)
 *
 * All async-safe, uses in-memory maps with periodic cleanup.
 */

import { log } from '@sentinel/core';
import type { RateLimitVerdict, DefenseConfig } from './types.js';
import { DEFAULT_DEFENSE_CONFIG } from './types.js';

interface IPWindow {
    timestamps: number[];       // request timestamps
    endpoints: Set<string>;     // unique endpoints seen
    errorCount: number;         // 4xx/5xx count
    totalCount: number;         // total request count
    windowStart: number;        // start of current window
}

export class RateLimiter {
    private windows: Map<string, IPWindow> = new Map();
    private config: DefenseConfig;

    constructor(config?: Partial<DefenseConfig>) {
        this.config = { ...DEFAULT_DEFENSE_CONFIG, ...config };

        // Cleanup stale entries every 60s
        const cleanup = setInterval(() => this.cleanup(), 60 * 1000);
        if (cleanup && typeof cleanup === 'object' && 'unref' in cleanup) cleanup.unref();
    }

    /**
     * Record a request and check if rate limits are exceeded.
     *
     * @param ip        - The real client IP
     * @param endpoint  - The requested endpoint (path)
     * @param statusCode - HTTP status code (0 if unknown)
     */
    check(ip: string, endpoint: string | null, statusCode: number = 0): RateLimitVerdict {
        const now = Date.now();
        const windowMs = this.config.rateLimit_windowSec * 1000;

        let window = this.windows.get(ip);
        if (!window || (now - window.windowStart > windowMs)) {
            // New window
            window = {
                timestamps: [],
                endpoints: new Set(),
                errorCount: 0,
                totalCount: 0,
                windowStart: now,
            };
            this.windows.set(ip, window);
        }

        // Record this request
        window.timestamps.push(now);
        window.totalCount++;
        if (endpoint) window.endpoints.add(endpoint);
        if (statusCode >= 400) window.errorCount++;

        // Prune old timestamps from this window
        const cutoff = now - windowMs;
        window.timestamps = window.timestamps.filter(t => t > cutoff);

        // ── Check 1: Request rate ──
        const requestsPerSec = window.timestamps.length / this.config.rateLimit_windowSec;
        if (requestsPerSec > this.config.rateLimit_requestsPerSec) {
            return {
                triggered: true,
                reason: `Request rate ${requestsPerSec.toFixed(1)}/s exceeds ${this.config.rateLimit_requestsPerSec}/s`,
                metric: 'request_rate',
                value: requestsPerSec,
                threshold: this.config.rateLimit_requestsPerSec,
            };
        }

        // ── Check 2: Endpoint scanning ──
        if (window.endpoints.size > this.config.rateLimit_uniqueEndpoints) {
            return {
                triggered: true,
                reason: `Endpoint scanning: ${window.endpoints.size} unique endpoints in ${this.config.rateLimit_windowSec}s`,
                metric: 'endpoint_scan',
                value: window.endpoints.size,
                threshold: this.config.rateLimit_uniqueEndpoints,
            };
        }

        // ── Check 3: Error rate ──
        if (window.totalCount >= 10) {  // Only check after minimum sample
            const errorRate = (window.errorCount / window.totalCount) * 100;
            if (errorRate > this.config.rateLimit_errorRatePercent) {
                return {
                    triggered: true,
                    reason: `Error rate ${errorRate.toFixed(0)}% exceeds ${this.config.rateLimit_errorRatePercent}% (${window.errorCount}/${window.totalCount})`,
                    metric: 'error_rate',
                    value: errorRate,
                    threshold: this.config.rateLimit_errorRatePercent,
                };
            }
        }

        return {
            triggered: false,
            reason: null,
            metric: null,
            value: 0,
            threshold: 0,
        };
    }

    /** Remove stale windows */
    private cleanup(): void {
        const now = Date.now();
        const maxAge = this.config.rateLimit_windowSec * 5 * 1000;
        for (const [ip, window] of this.windows.entries()) {
            if (now - window.windowStart > maxAge) {
                this.windows.delete(ip);
            }
        }
    }

    updateConfig(config: Partial<DefenseConfig>): void {
        this.config = { ...this.config, ...config };
    }
}
