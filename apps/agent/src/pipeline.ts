/**
 * Central Log Processing Pipeline
 *
 * Flow:
 *   LogLine → NoiseFilter → IPResolver → BotVerifier → RateLimiter
 *           → OWASPScanner → ThreatScorer → AIAnalysis → Blocker → StructuredLogger → Notifier
 *
 * v2: Integrated ThreatScoreAccumulator — bans only when score crosses threshold,
 *     not on single pattern matches. Reduces false positives dramatically.
 */

import { log, SentinelDB } from '@sentinel/core';
import { WebSocketServer, WebSocket } from 'ws';
import { resolveRealIP, extractSimpleIP, type ResolvedIP } from './ip/resolver.js';
import { isCloudflareIP } from './ip/cloudflare.js';
import { Blocker } from './defense/blocker.js';
import { RateLimiter } from './defense/rate-limiter.js';
import { ThreatScoreAccumulator, type ScoreResult, type RuleTier } from './defense/threat-score.js';
import { OWASPScanner, type OWASPMatch } from './rules.js';
import { AIManager } from './ai.js';
import { TelegramNotifier } from './telegram.js';
import { emitSecurityEvent } from './logging/structured.js';
import type { BlockAction } from './defense/types.js';

// ── HTTP Log Parsing Helpers ────────────────────────────────────

const HTTP_METHOD_PATTERN = /\"(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+([^\s]+)\s+HTTP/i;
const STATUS_CODE_PATTERN = /\"\s+(\d{3})\s+/;
const USER_AGENT_PATTERN = /\"([^"]*(?:Mozilla|bot|curl|wget|python|java|Go-http|axios)[^"]*)\"\?/i;

interface ParsedLogLine {
    method: string | null;
    endpoint: string | null;
    statusCode: number;
    userAgent: string | null;
}

function parseHTTPFields(line: string): ParsedLogLine {
    const methodMatch = line.match(HTTP_METHOD_PATTERN);
    const statusMatch = line.match(STATUS_CODE_PATTERN);
    const uaMatch = line.match(USER_AGENT_PATTERN);

    return {
        method: methodMatch ? methodMatch[1] : null,
        endpoint: methodMatch ? methodMatch[2] : null,
        statusCode: statusMatch ? parseInt(statusMatch[1], 10) : 0,
        userAgent: uaMatch ? uaMatch[1] : null,
    };
}

// ── Noise Filter ────────────────────────────────────────────────

const NOISY_PATTERNS = [
    'PHP Deprecated',
    'PHP Notice',
    'Stack trace',
    'Call to undefined function',
    'Creation of dynamic property',
    'Function _load_textdomain_just_in_time was called incorrectly',
    'Constant FILTER_SANITIZE_STRING is deprecated',
];

function isNoisy(line: string): boolean {
    return NOISY_PATTERNS.some(p => line.includes(p));
}

// ── Log Settings ────────────────────────────────────────────────

interface LogSettings {
    enabled: boolean;
    sampleRate: number;
    lineCount: number;
    filterHttp: boolean;
}

const logSettings = new Map<string, LogSettings>();

export function getSettings(filePath: string): LogSettings {
    if (!logSettings.has(filePath)) {
        logSettings.set(filePath, { enabled: true, sampleRate: 1, lineCount: 0, filterHttp: false });
    }
    return logSettings.get(filePath)!;
}

export function updateSettings(filePath: string, partial: Partial<LogSettings>): LogSettings {
    const current = getSettings(filePath);
    const updated = { ...current, ...partial };
    logSettings.set(filePath, updated);
    return updated;
}

// ── Pipeline Configuration ──────────────────────────────────────

export interface PipelineConfig {
    blocker: Blocker;
    rateLimiter: RateLimiter;
    threatScorer: ThreatScoreAccumulator;
    aiManager: AIManager;
    telegram: TelegramNotifier;
    wss: WebSocketServer;
    cloudClient: any;  // Optional CloudClient
    db: SentinelDB;
    isSafeMode: boolean;
    isWarmingUp: boolean;
}

let pipelineConfig: PipelineConfig | null = null;

export function initPipeline(config: PipelineConfig): void {
    pipelineConfig = config;
}

export function updatePipelineFlags(flags: { isSafeMode?: boolean; isWarmingUp?: boolean }): void {
    if (!pipelineConfig) return;
    if (flags.isSafeMode !== undefined) pipelineConfig.isSafeMode = flags.isSafeMode;
    if (flags.isWarmingUp !== undefined) pipelineConfig.isWarmingUp = flags.isWarmingUp;
}

// ── Exported for dashboard access ───────────────────────────────
export function getThreatScorer(): ThreatScoreAccumulator | null {
    return pipelineConfig?.threatScorer || null;
}

// ── Main Pipeline Entry ─────────────────────────────────────────

export async function processLogLine(line: string, filePath: string): Promise<void> {
    if (!pipelineConfig) return;
    const { blocker, rateLimiter, threatScorer, aiManager, telegram, wss, cloudClient, db, isSafeMode, isWarmingUp } = pipelineConfig;

    try {
        const settings = getSettings(filePath);
        if (!settings.enabled) return;

        const trimmed = line.trim();
        if (!trimmed) return;

        // ── Stage 1: Noise Filter ──
        if (isNoisy(trimmed)) return;

        // ── Stage 1.5: FTS5 Indexing ──
        db.indexLog(trimmed, filePath);

        // ── Stage 2: IP Resolution ──
        const isHttpLog = filePath.includes('access') || filePath.includes('nginx') || filePath.includes('apache') || filePath.includes('httpd');
        let resolved: ResolvedIP | null;

        if (isHttpLog) {
            resolved = resolveRealIP(trimmed);
        } else {
            const simpleIP = extractSimpleIP(trimmed);
            resolved = simpleIP ? { realIP: simpleIP, proxyIP: null, method: 'remote_addr' } : null;
        }

        if (!resolved) return; // No IP → discard

        const { realIP, proxyIP } = resolved;

        // ── Stage 3: Sampling ──
        settings.lineCount++;
        if (settings.sampleRate > 1 && settings.lineCount % settings.sampleRate !== 0) return;

        // ── Stage 4: HTTP Method Filter ──
        const httpFields = parseHTTPFields(trimmed);
        if (settings.filterHttp && !httpFields.method) return;

        // ── Stage 5: Rate Limiting ──
        const rateVerdict = rateLimiter.check(realIP, httpFields.endpoint, httpFields.statusCode);

        if (rateVerdict.triggered) {
            log(`[RateLimit] ⚡ ${realIP}: ${rateVerdict.reason}`);

            // Feed rate limit events into the score accumulator
            const scoreResult = threatScorer.addEvent(
                realIP, 'rate_limit', 'HIGH', rateVerdict.reason!, filePath
            );

            if (!isWarmingUp && scoreResult.shouldBlock) {
                const result = await blocker.evaluate({
                    ip: realIP,
                    realIP,
                    proxyIP,
                    userAgent: httpFields.userAgent,
                    endpoint: httpFields.endpoint,
                    method: httpFields.method,
                    risk: 'HIGH',
                    reason: `${rateVerdict.reason!} (Score: ${scoreResult.currentScore.toFixed(0)})`,
                    source: filePath,
                    immediate: rateVerdict.metric === 'request_rate',
                });

                const dryLabel = isSafeMode ? ' [DRY RUN]' : '';
                if (result && (result.action === 'temp_block' || result.action === 'perm_block')) {
                    const method = result.record.blockMethod || 'iptables';
                    telegram.notifyBan(realIP, `${rateVerdict.reason!} [Score: ${scoreResult.currentScore.toFixed(0)}, ${scoreResult.eventCount} events]${dryLabel}`, method);
                    emitBlockEvent(result.action, result.record.reason, resolved, httpFields, filePath);
                    broadcastAlert(wss, 'HIGH', `${rateVerdict.reason!}${dryLabel}`, realIP, filePath);
                }
            } else if (!isWarmingUp) {
                // Score didn't cross threshold — just log
                log(`[RateLimit] 📊 ${realIP}: Rate limit hit but score below threshold (${scoreResult.currentScore.toFixed(0)}/${threatScorer.resolveWeight('rate_limit', undefined) * 3})`);
            }

            emitSecurityEvent({
                timestamp: new Date().toISOString(),
                real_ip: realIP,
                proxy_ip: proxyIP,
                method: httpFields.method,
                endpoint: httpFields.endpoint,
                user_agent: httpFields.userAgent,
                risk: 'HIGH',
                action: isSafeMode ? 'dry_run_rate_limited' : 'rate_limited',
                reason: rateVerdict.reason!,
                source: filePath,
            });

            return;
        }

        // ── Stage 6: Threat Detection (OWASP + AI) ──
        let result: any = null;
        let isLocalMatch = false;
        let matchTier: RuleTier | null = null;
        let matchConfidence: string | undefined = undefined;

        const owaspMatches = OWASPScanner.scan(trimmed);
        if (owaspMatches.length > 0) {
            isLocalMatch = true;

            // Filter out noise-tier matches for decision making (still log them)
            const actionableMatches = owaspMatches.filter(m => m.tier !== 'noise');

            if (actionableMatches.length === 0) {
                // All matches were noise — don't escalate
                return;
            }

            const prioritized = actionableMatches.reduce((prev: OWASPMatch, curr: OWASPMatch) => {
                const risks: Record<string, number> = { 'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3 };
                return (risks[curr.risk] || 0) > (risks[prev.risk] || 0) ? curr : prev;
            }, actionableMatches[0]);

            matchTier = prioritized.tier;
            matchConfidence = prioritized.confidence;

            result = {
                risk: prioritized.risk,
                summary: `[OWASP ${prioritized.category}] ${prioritized.summary}`,
                ip: realIP,
                action: prioritized.action,
                immediate: prioritized.immediate,
                tokens: 0,
                usage: { totalTokens: aiManager.totalTokens, totalCost: aiManager.totalCost, requestCount: aiManager.requestCount },
                allMatches: actionableMatches,
                cves: actionableMatches.flatMap((m: OWASPMatch) => m.cve || []),
                tier: matchTier,
                confidence: matchConfidence,
            };
            log(`[Defense] 🛡️ OWASP: ${prioritized.category} [tier=${matchTier}] (Shield Mode).`);

        } else if (filePath.endsWith('auth.log') || filePath.endsWith('secure')) {
            if (/failed|failure|invalid user|authentication error|refused|disconnect/i.test(trimmed)) {
                matchTier = 'signal';
                matchConfidence = 'HIGH';
                result = {
                    risk: 'MEDIUM',
                    summary: 'Detected authentication failure (Local Rule)',
                    ip: realIP,
                    action: 'Accumulate',
                    tokens: 0,
                    tier: 'auth_failure' as RuleTier,
                    confidence: 'HIGH',
                    usage: { totalTokens: aiManager.totalTokens, totalCost: aiManager.totalCost, requestCount: aiManager.requestCount },
                };
            } else if (/Accepted (?:password|publickey|none) for root/i.test(trimmed)) {
                result = {
                    risk: 'CRITICAL',
                    summary: '🚨 SUCCESSFUL ROOT LOGIN',
                    ip: realIP,
                    action: 'Monitor',
                    tokens: 0,
                    tier: 'instant' as RuleTier,
                    confidence: 'HIGH',
                    usage: { totalTokens: aiManager.totalTokens, totalCost: aiManager.totalCost, requestCount: aiManager.requestCount },
                };
            }
        } else {
            // If AI is available, use it for deep analysis
            if (aiManager.initialized) {
                result = await aiManager.analyze(trimmed);
                if (result) {
                    // AI results default to 'signal' tier — they need accumulation
                    result.tier = result.risk === 'CRITICAL' ? 'instant' : 'signal';
                    result.confidence = 'MEDIUM';
                }
            } else {
                // Shield Mode Heuristic Fallback: catch obvious attacks without AI
                const suspiciousMethod = httpFields.method && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(httpFields.method);
                const staticTarget = httpFields.endpoint && /\.(html?|jpg|jpeg|png|gif|css|ico|svg|woff2?|ttf|eot)$/i.test(httpFields.endpoint);
                const suspiciousUA = httpFields.userAgent && /^(-|)$/.test(httpFields.userAgent.trim());

                if (suspiciousMethod && staticTarget) {
                    result = {
                        risk: 'MEDIUM',
                        summary: `[Shield] Suspicious ${httpFields.method} to static resource: ${httpFields.endpoint}`,
                        ip: realIP,
                        action: 'Monitor',
                        tokens: 0,
                        tier: 'noise' as RuleTier,
                        confidence: 'LOW',
                        usage: { totalTokens: 0, totalCost: 0, requestCount: 0 },
                    };
                } else if (suspiciousUA && httpFields.endpoint && !/\.(css|js|ico|png|jpg|svg|woff)$/i.test(httpFields.endpoint)) {
                    result = {
                        risk: 'LOW',
                        summary: `[Shield] Request with empty User-Agent to ${httpFields.endpoint}`,
                        ip: realIP,
                        action: 'Monitor',
                        tokens: 0,
                        tier: 'noise' as RuleTier,
                        confidence: 'LOW',
                        usage: { totalTokens: 0, totalCost: 0, requestCount: 0 },
                    };
                }
            }
        }

        if (!result) {
            // No threat detected — still log for audit
            return;
        }

        // ── Stage 7: Broadcast AI Stats ──
        broadcastAIStats(wss, aiManager);
        if (cloudClient && result.tokens) cloudClient.addTokens(result.tokens);

        if (result.risk === 'SAFE' || result.risk === 'LOW') return;

        log(`[AI ALERT] ${result.risk} on ${filePath}: ${result.summary}`);

        // ── Stage 8: Threat Score Accumulation ──
        const eventTier: RuleTier | 'rate_limit' | 'auth_failure' =
            result.tier === 'auth_failure' ? 'auth_failure' : (result.tier || 'signal');
        const scoreResult = threatScorer.addEvent(
            realIP, eventTier as any, result.confidence || matchConfidence, result.summary, filePath
        );

        // ── Stage 9: Alert Broadcasting ──
        // Only send Telegram alerts for HIGH+ risk OR when score > 50% of threshold
        const scoreRatio = scoreResult.currentScore / 80; // relative to default threshold
        const shouldAlert = result.risk === 'CRITICAL' || result.risk === 'HIGH' || scoreRatio > 0.5;

        broadcastAlert(wss, result.risk, result.summary, realIP, filePath);

        if (shouldAlert) {
            const scoreTag = ` [Score: ${scoreResult.currentScore.toFixed(0)}, ${scoreResult.eventCount} events]`;
            telegram.sendAlert(result.risk, `${result.summary}${scoreTag} (Source: ${filePath})`, realIP);
        }

        // ── Stage 10: Defense Execution (Score-Gated) ──
        const attackerIP = result.ip || realIP;
        if (attackerIP && scoreResult.shouldBlock) {
            if (isWarmingUp) {
                log(`[Safety] ⏳ WARMUP: Suppressed defense against ${attackerIP} (score: ${scoreResult.currentScore.toFixed(0)})`);
                result.action = 'Monitor Only (Warmup)';
            } else {
                const dryLabel = isSafeMode ? ' [DRY RUN]' : '';
                const blockResult = await blocker.evaluate({
                    ip: attackerIP,
                    realIP,
                    proxyIP,
                    userAgent: httpFields.userAgent,
                    endpoint: httpFields.endpoint,
                    method: httpFields.method,
                    risk: result.risk,
                    reason: `${result.summary} [Score: ${scoreResult.currentScore.toFixed(0)}, ${scoreResult.eventCount} events]`,
                    source: filePath,
                    immediate: scoreResult.isInstantBan,
                });

                if (blockResult) {
                    result.action = `${blockResult.action}${dryLabel}`;
                    if (blockResult.action === 'temp_block' || blockResult.action === 'perm_block') {
                        const method = blockResult.record.blockMethod || 'iptables';
                        const banMsg = `${result.summary} [Score: ${scoreResult.currentScore.toFixed(0)}, ${scoreResult.eventCount} events]${dryLabel}`;
                        telegram.notifyBan(attackerIP, banMsg, method);
                        if (cloudClient) {
                            cloudClient.sendAlert('IP_BLOCKED', `IP ${attackerIP} ${blockResult.action}${dryLabel} via ${method} (${result.risk}).`, {
                                ip: attackerIP, reason: result.summary, risk: result.risk, action: blockResult.action, dryRun: isSafeMode, blockMethod: method,
                                score: scoreResult.currentScore, eventCount: scoreResult.eventCount,
                            });
                        }
                    }
                }
            }
        } else if (attackerIP && !scoreResult.shouldBlock && (result.risk === 'MEDIUM' || result.risk === 'HIGH')) {
            // Score below threshold — just log, don't block
            result.action = `scored (${scoreResult.currentScore.toFixed(0)}/${80})`;
        }

        // ── Stage 11: Structured Log ──
        emitSecurityEvent({
            timestamp: new Date().toISOString(),
            real_ip: realIP,
            proxy_ip: proxyIP,
            method: httpFields.method,
            endpoint: httpFields.endpoint,
            user_agent: httpFields.userAgent,
            risk: result.risk,
            action: result.action || 'logged',
            reason: result.summary,
            source: filePath,
        });

        // ── Stage 12: Forensic Enrichment (async, non-blocking) ──
        if (isLocalMatch && aiManager.initialized) {
            enrichForensics(aiManager, wss, trimmed, result, { ...result, timestamp: new Date().toISOString(), source: filePath }, filePath);
        }

        // ── Stage 13: Dashboard History Update ──
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({ type: 'history_update' }));
            }
        });

    } catch (e) {
        log(`[Pipeline Error] ${e}`);
    }
}

// ── Helpers ──────────────────────────────────────────────────────

function broadcastAlert(wss: WebSocketServer, risk: string, summary: string, ip: string, source: string): void {
    const payload = JSON.stringify({
        type: 'alert',
        data: { risk, summary, ip, source, timestamp: new Date().toISOString() },
    });
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) client.send(payload);
    });
}

function broadcastAIStats(wss: WebSocketServer, ai: AIManager): void {
    const payload = JSON.stringify({
        type: 'ai_stats',
        data: {
            totalTokens: ai.totalTokens,
            totalCost: ai.totalCost,
            requestCount: ai.requestCount,
            model: ai.model,
        },
    });
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) client.send(payload);
    });
}

function enrichForensics(ai: AIManager, wss: WebSocketServer, line: string, result: any, alertData: any, source: string): void {
    (async () => {
        try {
            log(`[AI] ⚡ Forensic enrichment...`);
            const enriched = await ai.enrichAnalysis(line, result);
            if (enriched.isEnriched) {
                log(`[AI] 🧠 Forensics: ${enriched.forensics.target}`);
                const payload = JSON.stringify({
                    type: 'alert_update',
                    data: { ...enriched, timestamp: alertData.timestamp, source },
                });
                wss.clients.forEach((client: WebSocket) => {
                    if (client.readyState === WebSocket.OPEN) client.send(payload);
                });
            }
        } catch (e) {
            log(`[AI] Forensic enrichment failed: ${e}`);
        }
    })();
}

function emitBlockEvent(action: BlockAction, reason: string, resolved: ResolvedIP, http: ParsedLogLine, source: string): void {
    emitSecurityEvent({
        timestamp: new Date().toISOString(),
        real_ip: resolved.realIP,
        proxy_ip: resolved.proxyIP,
        method: http.method,
        endpoint: http.endpoint,
        user_agent: http.userAgent,
        risk: 'HIGH',
        action,
        reason,
        source,
    });
}
