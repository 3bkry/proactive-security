/**
 * Threat Score Accumulator — Confidence-Based IP Scoring Engine
 *
 * Replaces the old "one match = ban" approach with weighted scoring:
 *   - Each event adds points to an IP's threat score
 *   - Score decays over time (half-life model)
 *   - Ban only triggers when score crosses a configurable threshold
 *   - CRITICAL + HIGH confidence = instant ban (bypass accumulation)
 *
 * This eliminates false positives from single benign pattern matches
 * (e.g. Next.js headers, .env probes) while still catching persistent attackers.
 */

import { log } from '@sentinel/core';

// ── Score Weight Map ─────────────────────────────────────────────

export type RuleTier = 'instant' | 'strong' | 'signal' | 'noise';

export interface ScoreWeights {
    /** instant tier: known exploits, webshells, cryptominers */
    instant: number;
    /** strong tier: SQLi, XSS, RCE, OS cmd injection */
    strong_high_confidence: number;
    strong_medium_confidence: number;
    /** signal tier: info gathering, probing */
    signal: number;
    /** noise tier: FP-prone patterns */
    noise: number;
    /** Rate limiter trigger */
    rate_limit: number;
    /** Auth failure (SSH brute force) */
    auth_failure: number;
}

export const DEFAULT_SCORE_WEIGHTS: ScoreWeights = {
    instant: 100,
    strong_high_confidence: 40,
    strong_medium_confidence: 20,
    signal: 5,
    noise: 1,
    rate_limit: 30,
    auth_failure: 10,
};

// ── Event Tracking ──────────────────────────────────────────────

export interface ScoreEvent {
    timestamp: number;
    points: number;
    reason: string;
    tier: RuleTier | 'rate_limit' | 'auth_failure';
    source: string;
}

interface IPScoreEntry {
    /** Raw accumulated score (before decay) */
    rawScore: number;
    /** Timestamp of last score update */
    lastUpdate: number;
    /** Recent events for forensic context (kept capped) */
    events: ScoreEvent[];
    /** Number of times this IP has been banned */
    banCount: number;
}

export interface ScoreResult {
    /** Current effective score after decay */
    currentScore: number;
    /** Points added by this event */
    pointsAdded: number;
    /** Whether the IP should be blocked */
    shouldBlock: boolean;
    /** Whether this is an instant-ban scenario */
    isInstantBan: boolean;
    /** Human-readable reason for the decision */
    reason: string;
    /** Number of accumulated events */
    eventCount: number;
    /** Summary of top contributing events */
    topEvents: string[];
}

// ── Accumulator ──────────────────────────────────────────────────

export interface ThreatScoreConfig {
    /** Score threshold to trigger a ban (default: 80) */
    banThreshold: number;
    /** Score for instant-ban bypass (default: 100) */
    instantBanMinScore: number;
    /** Half-life for score decay in ms (default: 5 min) */
    decayIntervalMs: number;
    /** Max events kept per IP for forensics */
    maxEventsPerIP: number;
    /** Score weights */
    weights: ScoreWeights;
}

export const DEFAULT_THREAT_SCORE_CONFIG: ThreatScoreConfig = {
    banThreshold: 80,
    instantBanMinScore: 100,
    decayIntervalMs: 5 * 60 * 1000, // 5 minutes
    maxEventsPerIP: 20,
    weights: DEFAULT_SCORE_WEIGHTS,
};

export class ThreatScoreAccumulator {
    private scores: Map<string, IPScoreEntry> = new Map();
    private config: ThreatScoreConfig;

    constructor(config?: Partial<ThreatScoreConfig>) {
        this.config = { ...DEFAULT_THREAT_SCORE_CONFIG, ...config };
        if (config?.weights) {
            this.config.weights = { ...DEFAULT_SCORE_WEIGHTS, ...config.weights };
        }

        // Cleanup stale entries every 10 minutes
        const cleanup = setInterval(() => this.cleanup(), 10 * 60 * 1000);
        if (cleanup && typeof cleanup === 'object' && 'unref' in cleanup) cleanup.unref();
    }

    /**
     * Calculate the effective (decayed) score for an IP.
     * Uses exponential decay: score * 0.5^(elapsed / halfLife)
     */
    private getDecayedScore(entry: IPScoreEntry): number {
        if (entry.rawScore === 0) return 0;

        const elapsed = Date.now() - entry.lastUpdate;
        if (elapsed <= 0) return entry.rawScore;

        const halfLives = elapsed / this.config.decayIntervalMs;
        const decayed = entry.rawScore * Math.pow(0.5, halfLives);

        // Floor very small scores to 0
        return decayed < 0.5 ? 0 : decayed;
    }

    /**
     * Resolve the score weight for a given tier + confidence combination.
     */
    resolveWeight(tier: RuleTier | 'rate_limit' | 'auth_failure', confidence?: string): number {
        const w = this.config.weights;

        switch (tier) {
            case 'instant':
                return w.instant;
            case 'strong':
                return confidence === 'HIGH' ? w.strong_high_confidence : w.strong_medium_confidence;
            case 'signal':
                return w.signal;
            case 'noise':
                return w.noise;
            case 'rate_limit':
                return w.rate_limit;
            case 'auth_failure':
                return w.auth_failure;
            default:
                return w.signal; // safe fallback
        }
    }

    /**
     * Add a threat event for an IP and evaluate whether to block.
     */
    addEvent(
        ip: string,
        tier: RuleTier | 'rate_limit' | 'auth_failure',
        confidence: string | undefined,
        reason: string,
        source: string,
    ): ScoreResult {
        const now = Date.now();
        const points = this.resolveWeight(tier, confidence);

        // Get or create entry
        let entry = this.scores.get(ip);
        if (!entry) {
            entry = {
                rawScore: 0,
                lastUpdate: now,
                events: [],
                banCount: 0,
            };
            this.scores.set(ip, entry);
        }

        // Apply decay to existing score before adding new points
        const decayedBefore = this.getDecayedScore(entry);
        entry.rawScore = decayedBefore + points;
        entry.lastUpdate = now;

        // Record event
        const event: ScoreEvent = {
            timestamp: now,
            points,
            reason,
            tier,
            source,
        };
        entry.events.push(event);
        if (entry.events.length > this.config.maxEventsPerIP) {
            entry.events.shift(); // Remove oldest
        }

        // Decision logic
        const currentScore = entry.rawScore;
        const isInstantBan = tier === 'instant' && points >= this.config.instantBanMinScore;
        const shouldBlock = isInstantBan || currentScore >= this.config.banThreshold;

        // Build top events summary
        const topEvents = entry.events
            .slice(-5)
            .map(e => `[${e.tier}:+${e.points}] ${e.reason.substring(0, 80)}`);

        if (shouldBlock) {
            entry.banCount++;
            log(`[ThreatScore] 🎯 IP ${ip} crossed ban threshold: score=${currentScore.toFixed(1)} (threshold=${this.config.banThreshold}), events=${entry.events.length}`);
        } else if (points > 0) {
            log(`[ThreatScore] 📊 IP ${ip}: +${points}pts (${tier}) → score=${currentScore.toFixed(1)}/${this.config.banThreshold}`);
        }

        return {
            currentScore,
            pointsAdded: points,
            shouldBlock,
            isInstantBan,
            reason: shouldBlock
                ? `Threat score ${currentScore.toFixed(0)} exceeded threshold ${this.config.banThreshold} (${entry.events.length} events)`
                : `Score ${currentScore.toFixed(0)}/${this.config.banThreshold} — monitoring`,
            eventCount: entry.events.length,
            topEvents,
        };
    }

    /**
     * Get the current score for an IP (with decay applied).
     */
    getScore(ip: string): number {
        const entry = this.scores.get(ip);
        if (!entry) return 0;
        return this.getDecayedScore(entry);
    }

    /**
     * Get recent events for an IP (for forensic display).
     */
    getEvents(ip: string): ScoreEvent[] {
        return this.scores.get(ip)?.events || [];
    }

    /**
     * Reset score for an IP (e.g. after unban or whitelist).
     */
    resetScore(ip: string): void {
        this.scores.delete(ip);
    }

    /**
     * Update config at runtime (e.g. from Telegram command or dashboard).
     */
    updateConfig(partial: Partial<ThreatScoreConfig>): void {
        this.config = { ...this.config, ...partial };
        if (partial.weights) {
            this.config.weights = { ...this.config.weights, ...partial.weights };
        }
        log(`[ThreatScore] Config updated: threshold=${this.config.banThreshold}, decay=${this.config.decayIntervalMs}ms`);
    }

    /**
     * Remove stale entries (no activity in 30 minutes and score effectively 0).
     */
    private cleanup(): void {
        const now = Date.now();
        const staleThreshold = 30 * 60 * 1000; // 30 minutes

        for (const [ip, entry] of this.scores.entries()) {
            if (now - entry.lastUpdate > staleThreshold && this.getDecayedScore(entry) < 1) {
                this.scores.delete(ip);
            }
        }
    }

    /**
     * Get stats for dashboard/monitoring.
     */
    getStats(): { trackedIPs: number; hotIPs: { ip: string; score: number; events: number }[] } {
        const hotIPs: { ip: string; score: number; events: number }[] = [];

        for (const [ip, entry] of this.scores.entries()) {
            const score = this.getDecayedScore(entry);
            if (score > 5) {
                hotIPs.push({ ip, score: Math.round(score), events: entry.events.length });
            }
        }

        hotIPs.sort((a, b) => b.score - a.score);

        return {
            trackedIPs: this.scores.size,
            hotIPs: hotIPs.slice(0, 20),
        };
    }
}
