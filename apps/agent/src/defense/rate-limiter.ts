/**
 * Sliding-Window Rate Limiter
 *
 * Detects:
 *  - High request rate (> N req/sec)
 *  - Endpoint scanning (many unique endpoints rapidly)
 *  - High error rate (> X% 4xx/5xx)
 *
 * v2: Added per-IP alert cooldown — once triggered, suppresses redundant
 *     alerts for 60s to prevent log/Telegram flooding.
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

/** Tracks when we last alerted for each IP to avoid spam */
interface AlertCooldown {
    lastAlerted: number;
    metric: string;
}

export class RateLimiter {
    private windows: Map<string, IPWindow> = new Map();
    private cooldowns: Map<string, AlertCooldown> = new Map();
    private config: DefenseConfig;

    /** How long to suppress repeated alerts for the same IP (ms) */
    private readonly ALERT_COOLDOWN_MS = 60_000; // 60 seconds

    constructor(config?: Partial<DefenseConfig>) {
        this.config = { ...DEFAULT_DEFENSE_CONFIG, ...config };

        // Cleanup stale entries every 60s
        const cleanup = setInterval(() => this.cleanup(), 60 * 1000);
        if (cleanup && typeof cleanup === 'object' && 'unref' in cleanup) cleanup.unref();
    }

    /**
     * Record a request and check if rate limits are exceeded.
     * Returns triggered: true only ONCE per cooldown period per IP.
     *
     * @param ip         - The real client IP
     * @param endpoint   - The requested endpoint (path)
     * @param statusCode - HTTP status code (0 if unknown)
     * @param userAgent  - Optional user-agent for bot detection
     */
    check(ip: string, endpoint: string | null, statusCode: number = 0, userAgent?: string | null): RateLimitVerdict {
        const now = Date.now();
        const windowMs = this.config.rateLimit_windowSec * 1000;

        let window = this.windows.get(ip);
        if (!window || (now - window.windowStart > windowMs)) {
            // New window — also clear any old cooldown so fresh triggers can fire
            window = {
                timestamps: [],
                endpoints: new Set(),
                errorCount: 0,
                totalCount: 0,
                windowStart: now,
            };
            this.windows.set(ip, window);
            this.cooldowns.delete(ip);
        }

        // Record this request
        window.timestamps.push(now);
        window.totalCount++;
        if (endpoint) window.endpoints.add(endpoint);
        if (statusCode >= 400) window.errorCount++;

        // Prune old timestamps from this window
        const cutoff = now - windowMs;
        window.timestamps = window.timestamps.filter(t => t > cutoff);

        // ── Cooldown Check ──
        // If we already alerted for this IP recently, suppress further triggers
        const cooldown = this.cooldowns.get(ip);
        if (cooldown && (now - cooldown.lastAlerted < this.ALERT_COOLDOWN_MS)) {
            return NOT_TRIGGERED;
        }

        // ── Check 1: Request rate ──
        const requestsPerSec = window.timestamps.length / this.config.rateLimit_windowSec;
        if (requestsPerSec > this.config.rateLimit_requestsPerSec) {
            this.cooldowns.set(ip, { lastAlerted: now, metric: 'request_rate' });
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
            this.cooldowns.set(ip, { lastAlerted: now, metric: 'endpoint_scan' });
            return {
                triggered: true,
                reason: `Endpoint scanning: ${window.endpoints.size} unique endpoints in ${this.config.rateLimit_windowSec}s`,
                metric: 'endpoint_scan',
                value: window.endpoints.size,
                threshold: this.config.rateLimit_uniqueEndpoints,
            };
        }

        // ── Check 3: Error rate ──
        // Minimum sample: 30 requests (was 10 — too low, triggers on Googlebot with a few 404s)
        if (window.totalCount >= 30) {
            // Skip error-rate check for known search engine bots
            if (userAgent && /googlebot|bingbot|slurp|duckduckbot|yandexbot|baiduspider/i.test(userAgent)) {
                // Bots hitting 404s is normal behavior — don't flag
                return NOT_TRIGGERED;
            }

            const errorRate = (window.errorCount / window.totalCount) * 100;
            if (errorRate > this.config.rateLimit_errorRatePercent) {
                this.cooldowns.set(ip, { lastAlerted: now, metric: 'error_rate' });
                return {
                    triggered: true,
                    reason: `Error rate ${errorRate.toFixed(0)}% exceeds ${this.config.rateLimit_errorRatePercent}% (${window.errorCount}/${window.totalCount})`,
                    metric: 'error_rate',
                    value: errorRate,
                    threshold: this.config.rateLimit_errorRatePercent,
                };
            }
        }

        return NOT_TRIGGERED;
    }

    /** Remove stale windows and cooldowns */
    private cleanup(): void {
        const now = Date.now();
        const maxAge = this.config.rateLimit_windowSec * 5 * 1000;
        for (const [ip, window] of this.windows.entries()) {
            if (now - window.windowStart > maxAge) {
                this.windows.delete(ip);
                this.cooldowns.delete(ip);
            }
        }
        // Also cleanup cooldowns older than 5 minutes
        for (const [ip, cd] of this.cooldowns.entries()) {
            if (now - cd.lastAlerted > 5 * 60 * 1000) {
                this.cooldowns.delete(ip);
            }
        }
    }

    updateConfig(config: Partial<DefenseConfig>): void {
        this.config = { ...this.config, ...config };
    }
}

/** Shared singleton to avoid object creation on every check */
const NOT_TRIGGERED: RateLimitVerdict = {
    triggered: false,
    reason: null,
    metric: null,
    value: 0,
    threshold: 0,
};
