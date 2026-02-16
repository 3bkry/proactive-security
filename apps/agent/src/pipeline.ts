/**
 * Central Log Processing Pipeline
 *
 * Flow:
 *   LogLine → NoiseFilter → IPResolver → BotVerifier → RateLimiter
 *           → OWASPScanner → AIAnalysis → Blocker → StructuredLogger → Notifier
 *
 * This replaces the monolithic handleLogLine() from index.ts.
 */

import { log } from '@sentinel/core';
import { WebSocketServer, WebSocket } from 'ws';
import { resolveRealIP, extractSimpleIP, type ResolvedIP } from './ip/resolver.js';
import { isCloudflareIP } from './ip/cloudflare.js';
import { Blocker } from './defense/blocker.js';
import { RateLimiter } from './defense/rate-limiter.js';
import { OWASPScanner, type OWASPMatch } from './rules.js';
import { AIManager } from './ai.js';
import { TelegramNotifier } from './telegram.js';
import { emitSecurityEvent } from './logging/structured.js';
import type { BlockAction } from './defense/types.js';

// ── HTTP Log Parsing Helpers ────────────────────────────────────

const HTTP_METHOD_PATTERN = /\"(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+([^\s]+)\s+HTTP/i;
const STATUS_CODE_PATTERN = /\"\s+(\d{3})\s+/;
const USER_AGENT_PATTERN = /\"([^"]*(?:Mozilla|bot|curl|wget|python|java|Go-http|axios)[^"]*)\"?/i;

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
    aiManager: AIManager;
    telegram: TelegramNotifier;
    wss: WebSocketServer;
    cloudClient: any;  // Optional CloudClient
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

// ── Main Pipeline Entry ─────────────────────────────────────────

export async function processLogLine(line: string, filePath: string): Promise<void> {
    if (!pipelineConfig) return;
    const { blocker, rateLimiter, aiManager, telegram, wss, cloudClient, isSafeMode, isWarmingUp } = pipelineConfig;

    try {
        const settings = getSettings(filePath);
        if (!settings.enabled) return;

        const trimmed = line.trim();
        if (!trimmed) return;

        // ── Stage 1: Noise Filter ──
        if (isNoisy(trimmed)) return;

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

            if (!isWarmingUp) {
                const result = await blocker.evaluate({
                    ip: realIP,
                    realIP,
                    proxyIP,
                    userAgent: httpFields.userAgent,
                    endpoint: httpFields.endpoint,
                    method: httpFields.method,
                    risk: 'HIGH',
                    reason: rateVerdict.reason!,
                    source: filePath,
                    immediate: rateVerdict.metric === 'request_rate',
                });

                const dryLabel = isSafeMode ? ' [DRY RUN]' : '';
                if (result && (result.action === 'temp_block' || result.action === 'perm_block')) {
                    telegram.notifyBan(realIP, `${rateVerdict.reason!}${dryLabel}`);
                    emitBlockEvent(result.action, result.record.reason, resolved, httpFields, filePath);
                    broadcastAlert(wss, 'HIGH', `${rateVerdict.reason!}${dryLabel}`, realIP, filePath);
                }
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

        const owaspMatches = OWASPScanner.scan(trimmed);
        if (owaspMatches.length > 0) {
            isLocalMatch = true;
            const prioritized = owaspMatches.reduce((prev: OWASPMatch, curr: OWASPMatch) => {
                const risks: Record<string, number> = { 'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3 };
                return (risks[curr.risk] || 0) > (risks[prev.risk] || 0) ? curr : prev;
            }, owaspMatches[0]);

            result = {
                risk: prioritized.risk,
                summary: `[OWASP ${prioritized.category}] ${prioritized.summary}`,
                ip: realIP,
                action: prioritized.action,
                immediate: prioritized.immediate,
                tokens: 0,
                usage: { totalTokens: aiManager.totalTokens, totalCost: aiManager.totalCost, requestCount: aiManager.requestCount },
                allMatches: owaspMatches,
                cves: owaspMatches.flatMap((m: OWASPMatch) => m.cve || []),
            };
            log(`[Defense] 🛡️ OWASP: ${prioritized.category} (Shield Mode).`);

        } else if (filePath.endsWith('auth.log') || filePath.endsWith('secure')) {
            if (/failed|failure|invalid user|authentication error|refused|disconnect/i.test(trimmed)) {
                result = {
                    risk: 'HIGH',
                    summary: 'Detected repeated authentication failure (Local Rule)',
                    ip: realIP,
                    action: 'Ban IP if repeated',
                    tokens: 0,
                    usage: { totalTokens: aiManager.totalTokens, totalCost: aiManager.totalCost, requestCount: aiManager.requestCount },
                };
            }
        } else {
            result = await aiManager.analyze(trimmed);
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

        // ── Stage 8: Alert Broadcasting ──
        const alertData = { ...result, timestamp: new Date().toISOString(), source: filePath };
        broadcastAlert(wss, result.risk, result.summary, realIP, filePath);

        if (result.risk === 'CRITICAL' || result.risk === 'HIGH' || result.risk === 'MEDIUM') {
            telegram.sendAlert(result.risk, `${result.summary} (Source: ${filePath})`, realIP);
        }

        // ── Stage 9: Defense Execution ──
        const attackerIP = result.ip || realIP;
        if (attackerIP && (result.risk === 'CRITICAL' || result.risk === 'HIGH' || result.risk === 'MEDIUM')) {
            if (isWarmingUp) {
                log(`[Safety] ⏳ WARMUP: Suppressed defense against ${attackerIP}`);
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
                    reason: result.summary,
                    source: filePath,
                    immediate: result.immediate,
                });

                if (blockResult) {
                    result.action = `${blockResult.action}${dryLabel}`;
                    if (blockResult.action === 'temp_block' || blockResult.action === 'perm_block') {
                        telegram.notifyBan(attackerIP, `${result.summary}${dryLabel}`);
                        if (cloudClient) {
                            cloudClient.sendAlert('IP_BLOCKED', `IP ${attackerIP} ${blockResult.action}${dryLabel} (${result.risk}).`, {
                                ip: attackerIP, reason: result.summary, risk: result.risk, action: blockResult.action, dryRun: isSafeMode,
                            });
                        }
                    }
                }
            }
        }

        // ── Stage 10: Structured Log ──
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

        // ── Stage 11: Forensic Enrichment (async, non-blocking) ──
        if (isLocalMatch && aiManager.initialized) {
            enrichForensics(aiManager, wss, trimmed, result, alertData, filePath);
        }

        // ── Stage 12: Dashboard History Update ──
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
