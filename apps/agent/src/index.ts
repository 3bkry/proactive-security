/**
 * SentinelAI Agent — Main Orchestrator
 *
 * Slim entrypoint that wires together:
 *  - WebSocket server (dashboard communication)
 *  - Pipeline (log processing engine)
 *  - Blocker (progressive defense + whitelist)
 *  - Cloudflare IP resolution
 *  - Telegram bot commands
 *  - Cloud client (satellite mode)
 *  - File watcher + state persistence
 */

import "dotenv/config";
import { log } from '@sentinel/core';

// ── Global Safety Net ───────────────────────────────────────────
// Prevent the agent from exiting on unhandled promise rejections
// (e.g. transient network timeouts in third-party libraries).
process.on('unhandledRejection', (reason, promise) => {
    log(`[Sentinel] ⚠️ UNHANDLED REJECTION: ${reason}`);
});

import { WebSocketServer, WebSocket } from "ws";
import * as fs from 'fs';
import os from 'os';
import path from 'path';
import { LogWatcher } from "./watcher.js";
import { AIManager } from "./ai.js";
import {
    getSystemStats,
    CONFIG_FILE,
    STATE_FILE,
    SENTINEL_DATA_DIR,
    SentinelDB,
} from '@sentinel/core';
import { Blocker } from "./defense/blocker.js";
import { RateLimiter } from "./defense/rate-limiter.js";
import { TelegramNotifier } from "./telegram.js";
import { HeartbeatService } from "./heartbeat.js";
import { initCloudflareRanges } from "./ip/cloudflare.js";
import { setTrustedProxies } from "./ip/resolver.js";
import { initPipeline, processLogLine, getSettings, updateSettings, updatePipelineFlags } from "./pipeline.js";
import { readRecentEvents } from "./logging/structured.js";
import pty from "node-pty";

// ── WebSocket Server ────────────────────────────────────────────

const startWebSocketServer = async (startPort: number): Promise<{ wss: WebSocketServer, port: number }> => {
    return new Promise((resolve, reject) => {
        const server = new WebSocketServer({ port: startPort });
        server.on('listening', () => {
            log(`[Sentinel] WebSocket server listening on port ${startPort}`);
            resolve({ wss: server, port: startPort });
        });
        server.on('error', (err: any) => {
            if (err.code === 'EADDRINUSE') {
                log(`[Sentinel] Port ${startPort} in use. Trying ${startPort + 1}...`);
                server.close();
                if (startPort > 8100) { reject(new Error("No available port in 8081-8100")); return; }
                startWebSocketServer(startPort + 1).then(resolve).catch(reject);
            } else reject(err);
        });
    });
};

const { wss, port: selectedPort } = await startWebSocketServer(8081);

// ── Safety & Warmup ─────────────────────────────────────────────

const args = process.argv.slice(2);
const isSafeMode = args.includes("--safe") || fs.existsSync("/etc/sentinel/SAFE_MODE");
const WARMUP_DELAY_MS = 60000;
let isWarmingUp = true;

if (isSafeMode) {
    log("[Safety] 🛡️ STARTING IN SAFE MODE: Active enforcement disabled.");
} else {
    log(`[Safety] ⏳ Warming up for ${WARMUP_DELAY_MS / 1000}s (Detection Only)...`);
    setTimeout(() => {
        isWarmingUp = false;
        updatePipelineFlags({ isWarmingUp: false });
        log("[Safety] ✅ Warmup complete. Active Defense engaged.");
    }, WARMUP_DELAY_MS);
}

// ── Initialize Components ────────────────────────────────────────

import { ResourceMonitor } from "./monitor.js";
import { CloudClient } from "./cloud.js";

const watcher = new LogWatcher();
const aiManager = new AIManager();

// Load defense config from config.json if present
let defenseConfig: any = {};
let cfAPIConfig: { apiKey?: string; email?: string; apiToken?: string; zoneId?: string } | undefined;
if (fs.existsSync(CONFIG_FILE)) {
    try {
        const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
        if (config.defense) defenseConfig = config.defense;
        if (config.TRUSTED_PROXIES) setTrustedProxies(config.TRUSTED_PROXIES);
        // Cloudflare API config (optional — supports Global Key or API Token)
        if (config.CF_API_KEY && config.CF_EMAIL) {
            cfAPIConfig = { apiKey: config.CF_API_KEY, email: config.CF_EMAIL };
            log("[Config] ☁️ Cloudflare Global API Key configured — zones auto-discovered.");
        } else if (config.CF_API_TOKEN && config.CF_ZONE_ID) {
            cfAPIConfig = { apiToken: config.CF_API_TOKEN, zoneId: config.CF_ZONE_ID };
            log("[Config] ☁️ Cloudflare API Token configured.");
        }
    } catch (e) { /* ok */ }
}

const blocker = new Blocker({
    defense: defenseConfig,
    dryRun: isSafeMode,
    cloudflareAPI: cfAPIConfig,
});
const rateLimiter = new RateLimiter(defenseConfig);

// Threat Score Accumulator — replaces one-hit banning with confidence-based scoring
import { ThreatScoreAccumulator } from './defense/threat-score.js';
const threatScoreConfig = defenseConfig.threatScore || {};
const threatScorer = new ThreatScoreAccumulator(threatScoreConfig);
log(`[Defense] 📊 ThreatScore engine initialized (threshold: ${threatScoreConfig.banThreshold || 80})`);

const telegram = new TelegramNotifier(blocker as any); // Blocker has compatible API
const heartbeat = new HeartbeatService(wss);
const monitor = new ResourceMonitor(telegram);
const dbPath = path.join(SENTINEL_DATA_DIR, 'sentinel.db');
const db = new SentinelDB(dbPath);

// ── Initialize Cloudflare Ranges ─────────────────────────────────
await initCloudflareRanges();

// ── Initialize Pipeline ──────────────────────────────────────────

// Cloud Client Setup
let cloudUrl = process.env.SENTINEL_CLOUD_URL;
let agentKey = process.env.SENTINEL_AGENT_KEY;

if (fs.existsSync(CONFIG_FILE)) {
    try {
        const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
        if (!cloudUrl && config.SENTINEL_CLOUD_URL) cloudUrl = config.SENTINEL_CLOUD_URL;
        if (!agentKey && config.SENTINEL_AGENT_KEY) agentKey = config.SENTINEL_AGENT_KEY;
    } catch (e) {
        log(`[Config] Failed to read config file: ${e}`);
    }
}

let cloudClient: CloudClient | null = null;

if (cloudUrl && agentKey) {
    log(`[Cloud] Configuration found. Initializing Cloud Client...`);
    cloudClient = new CloudClient(cloudUrl, agentKey, selectedPort);

    cloudClient.connect().then(connected => {
        if (connected && cloudClient) {
            log("[Cloud] Agent acts as a satellite node.");
            const activeCloudClient = cloudClient;

            activeCloudClient.setCommandCallback(async (cmd) => {
                if (cmd.type === "BAN_IP") {
                    const ip = cmd.payload ? JSON.parse(cmd.payload).ip : null;
                    if (ip) {
                        await blocker.evaluate({
                            ip, realIP: ip, proxyIP: null, userAgent: null,
                            endpoint: null, method: null, risk: 'HIGH',
                            reason: 'via Cloud Dashboard', source: 'cloud', immediate: true,
                        });
                        telegram.notifyBan(ip, "via Cloud Dashboard");
                        return { success: true };
                    }
                } else if (cmd.type === "UNBAN_IP") {
                    const ip = cmd.payload ? JSON.parse(cmd.payload).ip : null;
                    if (ip) {
                        await blocker.unblock(ip);
                        return { success: true };
                    }
                }
                throw new Error("Unknown command");
            });

            activeCloudClient.setPulseDataGetter(() => {
                const files = watcher.getWatchedFiles().map(f => ({
                    path: f,
                    lastUpdate: fs.existsSync(f) ? fs.statSync(f).mtime.toISOString() : undefined
                }));
                return { files };
            });

            activeCloudClient.setOnSync((data: any) => {
                if (data.thresholds) monitor.updateConfig(data.thresholds);
                if (data.aiConfig) {
                    aiManager.updateConfig({
                        provider: data.aiConfig.provider,
                        geminiKey: data.aiConfig.geminiKey,
                        openaiKey: data.aiConfig.openaiKey,
                        zhipuKey: data.aiConfig.zhipuKey,
                        model: data.aiConfig.model
                    });
                }
                if (data.files) {
                    for (const file of data.files) {
                        if (file.enabled) watcher.add(file.path);
                        else watcher.remove(file.path);
                    }
                }
            });
        }
    });
}

// Wire up the pipeline with all components
initPipeline({
    blocker,
    rateLimiter,
    threatScorer,
    aiManager,
    telegram,
    wss,
    cloudClient,
    db,
    isSafeMode,
    isWarmingUp,
});

// ── Telegram Commands ────────────────────────────────────────────

telegram.onCommand("status", async () => {
    const stats = await getSystemStats();
    const blockedCount = blocker.getBlockedIPs().length;
    const aiMode = aiManager.initialized ? '🧠 Neural (AI Active)' : '🛡️ Shield (Local Rules Only)';
    const msg = `🖥️ *Server Status*\n\n` +
        `*Mode:* ${aiMode}\n` +
        `*CPUs:* ${stats.cpus}\n` +
        `*CPU Load:* ${stats.cpu.load}%\n` +
        `*Memory:* ${stats.memory.usagePercent}%\n` +
        `*Storage:* ${stats.disk.usagePercent}%\n` +
        `*Uptime:* ${Math.floor(stats.uptime / 3600)}h ${Math.floor((stats.uptime % 3600) / 60)}m\n` +
        `*Blocked IPs:* ${blockedCount}\n` +
        `*Active Watchers:* ${watcher.getWatchedFiles().length}`;
    telegram.sendMessage(msg);
});

telegram.onCommand("stats", () => {
    const msg = `🧠 *AI Analytics*\n\n` +
        `*Requests:* ${aiManager.requestCount}\n` +
        `*Total Tokens:* ${aiManager.totalTokens.toLocaleString()}\n` +
        `*Est. Cost:* $${aiManager.totalCost.toFixed(4)}\n` +
        `*Active Model:* \`${aiManager.model}\``;
    telegram.sendMessage(msg);
});

telegram.onCommand("banned", () => {
    const records = blocker.getBlockRecords();
    if (records.length === 0) {
        telegram.sendMessage("✅ *No IPs currently blocked.*");
        return;
    }

    const methodIcons: Record<string, string> = {
        'cloudflare_api': '☁️',
        'nginx_deny': '🌐',
        'apache_deny': '🌐',
        'iptables': '🔥',
    };

    const lines = records.map(r => {
        const icon = methodIcons[r.blockMethod || 'iptables'] || '🔥';
        const type = r.action === 'perm_block' ? '🔴 PERM' : '🟡 TEMP';
        return `• \`${r.ip}\` ${icon} ${type}`;
    });

    const msg = `🚫 *Blocked IPs (${records.length})*\n\n` + lines.join("\n");

    const options: any = { parse_mode: 'Markdown' };
    if (records.length > 0) {
        options.reply_markup = {
            inline_keyboard: [[{ text: "🔓 Unban All", callback_data: "unban_all" }]]
        };
    }

    telegram.sendMessage(msg, options);
});

// ── Ban Report Command ──────────────────────────────────────────
import { loadBanReports, getRecentBansPage, getBansForIP, getBanCount, formatReportCompact, formatReportForTelegram } from './defense/ban-report.js';
loadBanReports(); // Load persisted ban reports on startup

const PAGE_SIZE = 50;

/** Send a page of ban reports */
function sendReportPage(page: number) {
    const { entries, total, hasMore } = getRecentBansPage(page, PAGE_SIZE);

    if (entries.length === 0 && page === 0) {
        telegram.sendMessage("📋 No ban records yet. The system hasn't banned any IPs since the report module was activated.", {});
        return;
    }
    if (entries.length === 0) {
        telegram.sendMessage("📋 No more records.", {});
        return;
    }

    const from = page * PAGE_SIZE + 1;
    const to = page * PAGE_SIZE + entries.length;
    const header = `📋 Ban Report — ${from}-${to} of ${total}\n\n`;

    // Build compact list
    const lines = entries.map((b, i) => formatReportCompact(b, from + i));

    // Split into chunks that fit Telegram's 4096 char limit
    let chunk = header;
    for (const line of lines) {
        if (chunk.length + line.length + 2 > 3900) {
            telegram.sendMessage(chunk, {});
            chunk = '';
        }
        chunk += line + '\n';
    }

    // Send last chunk with "Load More" button if there are more
    const opts: any = {};
    if (hasMore) {
        opts.reply_markup = {
            inline_keyboard: [[{ text: `📄 Load More (${to + 1}–${Math.min(to + PAGE_SIZE, total)})`, callback_data: `rpt_${page + 1}` }]]
        };
    }
    if (chunk) {
        if (hasMore) {
            chunk += `\n💡 Use /report <IP> for full details on any IP.`;
        }
        telegram.sendMessage(chunk, opts);
    }
}

telegram.onCommand("report", (msg) => {
    const cmdArgs = msg.text?.split(" ") || [];
    const arg = cmdArgs[1];

    // /report <IP> — show full details for a specific IP
    if (arg && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(arg)) {
        const bans = getBansForIP(arg);
        if (bans.length === 0) {
            telegram.sendMessage(`📋 No ban records found for ${arg}.`, {});
            return;
        }
        const header = `📋 Ban Reports for ${arg} (${bans.length} total)\n\n`;
        // Show detailed view, split into messages if needed
        let detailMsg = header;
        for (let i = 0; i < Math.min(bans.length, 10); i++) {
            const entry = formatReportForTelegram(bans[i], i + 1);
            if (detailMsg.length + entry.length + 30 > 3900) {
                telegram.sendMessage(detailMsg, {});
                detailMsg = '';
            }
            detailMsg += entry + '\n\n─────────────────\n\n';
        }
        if (bans.length > 10) {
            detailMsg += `... and ${bans.length - 10} more records.`;
        }
        if (detailMsg) telegram.sendMessage(detailMsg, {});
        return;
    }

    // /report [page] — default page 0
    const page = arg ? Math.max(0, parseInt(arg, 10) - 1) : 0;
    sendReportPage(isNaN(page) ? 0 : page);
});

// Handle "Load More" button clicks for ban reports
telegram.onCallback('report_page', (page: number) => {
    sendReportPage(page);
});

telegram.onCommand("whitelist", (msg) => {
    const cmdArgs = msg.text?.split(" ") || [];
    const action = cmdArgs[1]; // add, remove, list
    const ip = cmdArgs[2];

    if (!action || action === "list") {
        const wl = blocker.getWhitelist();
        if (wl.length === 0) {
            telegram.sendMessage("📋 *Whitelist is empty.*");
        } else {
            telegram.sendMessage(`📋 *Whitelisted IPs (${wl.length}):*\n` + wl.map(i => `• \`${i}\``).join("\n"));
        }
        return;
    }

    if (!ip) {
        telegram.sendMessage("⚠️ Usage: `/whitelist <add|remove> <IP>`");
        return;
    }

    if (action === "add") {
        const added = blocker.addToWhitelist(ip);
        if (added) {
            telegram.sendMessage(`✅ Added \`${ip}\` to whitelist.`);
        } else {
            telegram.sendMessage(`ℹ️ \`${ip}\` is already whitelisted.`);
        }
    } else if (action === "remove") {
        const removed = blocker.removeFromWhitelist(ip);
        if (removed) {
            telegram.sendMessage(`🗑️ Removed \`${ip}\` from whitelist.`);
        } else {
            telegram.sendMessage(`ℹ️ \`${ip}\` was not in the whitelist.`);
        }
    }
});

telegram.onCommand("safelist", (msg) => {
    const cmdArgs = msg.text?.split(" ") || [];
    const action = cmdArgs[1]; // add, remove, list
    const keyword = cmdArgs.slice(2).join(" "); // allow multi-word keywords like "te data"

    if (!action || action === "list") {
        const { baseline, custom } = blocker.getSafeKeywords();
        let message = `🛡️ *Safe ISP Keywords (Whois Protection)*\n\n`;
        message += `*Built-in (always protected):*\n` + baseline.map(k => `• \`${k}\``).join("\n");
        if (custom.length > 0) {
            message += `\n\n*Custom (your additions):*\n` + custom.map(k => `• \`${k}\``).join("\n");
        } else {
            message += `\n\n_No custom keywords added yet._`;
        }
        message += `\n\n💡 _Use_ \`/safelist add <keyword>\` _to protect an ISP._`;
        telegram.sendMessage(message);
        return;
    }

    if (!keyword) {
        telegram.sendMessage("⚠️ Usage: `/safelist <add|remove> <keyword>`\n\nExample: `/safelist add te data`");
        return;
    }

    if (action === "add") {
        const added = blocker.addSafeKeyword(keyword);
        if (added) {
            telegram.sendMessage(`✅ Added \`${keyword}\` to safe ISP list.\n_IPs matching this in whois won't be auto-banned._`);
        } else {
            telegram.sendMessage(`ℹ️ \`${keyword}\` is already in the safe list (or is a built-in keyword).`);
        }
    } else if (action === "remove") {
        const removed = blocker.removeSafeKeyword(keyword);
        if (removed) {
            telegram.sendMessage(`🗑️ Removed \`${keyword}\` from safe ISP list.`);
        } else {
            telegram.sendMessage(`ℹ️ \`${keyword}\` was not in the custom safe list (built-in keywords can't be removed).`);
        }
    } else {
        telegram.sendMessage("⚠️ Usage: `/safelist <add|remove|list> [keyword]`");
    }
});

telegram.onCommand("watch", (msg) => {
    const cmdArgs = msg.text?.split(" ") || [];
    const action = cmdArgs[1];
    const watchPath = cmdArgs[2];

    if (!action || action === "list") {
        const files = watcher.getWatchedFiles();
        if (files.length === 0) telegram.sendMessage("📂 *No files currently watched.*");
        else telegram.sendMessage(`📂 *Watched Files:*\n` + files.map(f => `• \`${f}\``).join("\n"));
        return;
    }

    if (!watchPath) {
        telegram.sendMessage("⚠️ Usage: `/watch <add|remove> <path>`");
        return;
    }

    if (action === "add") {
        if (!fs.existsSync(watchPath)) {
            telegram.sendMessage(`❌ File not found: \`${watchPath}\``);
            return;
        }
        watcher.add(watchPath);
        telegram.sendMessage(`✅ Added to watchlist: \`${watchPath}\``);
    } else if (action === "remove") {
        watcher.remove(watchPath);
        telegram.sendMessage(`🗑️ Removed from watchlist: \`${watchPath}\``);
    }
});

telegram.onCommand("config", (msg) => {
    const cmdArgs = msg.text?.split(" ") || [];
    const key = cmdArgs[1]?.toLowerCase();
    const val = parseInt(cmdArgs[2]);

    if (!key || isNaN(val)) {
        telegram.sendMessage("⚠️ Usage: `/config <cpu|memory|disk> <percentage>`\nExample: `/config cpu 90`");
        return;
    }

    if (key === 'cpu') monitor.thresholds.cpu = val;
    else if (key === 'memory') monitor.thresholds.memory = val;
    else if (key === 'disk') monitor.thresholds.disk = val;
    else {
        telegram.sendMessage("⚠️ Invalid key. Use cpu, memory, or disk.");
        return;
    }

    telegram.sendMessage(`✅ Updated *${key.toUpperCase()}* threshold to **${val}%**`);
});

// Start Monitor & Heartbeat
monitor.start();
heartbeat.start();

// ── Dashboard WebSocket Handler ──────────────────────────────────

wss.on("connection", async (ws) => {
    log("Client connected to Sentinel Agent");

    const shell = process.env.SHELL || "bash";
    const terminal = (pty as any).spawn(shell, [], {
        name: "xterm-color", cols: 80, rows: 24,
        cwd: process.env.HOME, env: process.env
    });

    const onData = (data: string) => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "terminal", data }));
        }
    };
    terminal.on("data", onData);

    ws.on("message", (message) => {
        try {
            const msg = JSON.parse(message.toString());

            if (msg.type === "terminal") {
                terminal.write(msg.data);
            } else if (msg.type === "resize") {
                terminal.resize(msg.cols, msg.rows);
            } else if (msg.type === "get_watched_files") {
                const files = watcher.getWatchedFiles().map(f => ({
                    path: f,
                    stats: fs.existsSync(f) ? fs.statSync(f) : null,
                    settings: getSettings(f)
                }));
                ws.send(JSON.stringify({ type: "watched_files", data: files }));
            } else if (msg.type === "get_ai_history") {
                ws.send(JSON.stringify({ type: "ai_history", data: aiManager.history }));
            } else if (msg.type === "get_ai_prompt") {
                ws.send(JSON.stringify({ type: "ai_prompt", data: aiManager.promptTemplate }));
            } else if (msg.type === "update_ai_prompt") {
                aiManager.promptTemplate = msg.data;
                log("[AI] Prompt template updated");
                ws.send(JSON.stringify({ type: "prompt_updated", data: aiManager.promptTemplate }));
            } else if (msg.type === "discover_logs") {
                const discovered = LogWatcher.discoverFiles().map(f => ({
                    path: f,
                    stats: fs.existsSync(f) ? fs.statSync(f) : null,
                    watched: watcher.getWatchedFiles().includes(f)
                }));
                ws.send(JSON.stringify({ type: "discovered_files", data: discovered }));
            } else if (msg.type === "update_log_options") {
                const { path: logPath, enabled, sampleRate, filterHttp } = msg.data;
                const updated = updateSettings(logPath, { enabled, sampleRate, filterHttp });

                if (updated.enabled) watcher.add(logPath);
                else watcher.remove(logPath);

                ws.send(JSON.stringify({ type: "options_updated", data: { path: logPath, settings: updated } }));
            } else if (msg.type === "read_log_file") {
                const { path: logPath, lines } = msg.data;
                if (fs.existsSync(logPath)) {
                    const content = fs.readFileSync(logPath, 'utf-8');
                    const allLines = content.split('\n');
                    const lastLines = allLines.slice(-(lines || 100)).join('\n');
                    ws.send(JSON.stringify({ type: "log_content", data: { path: logPath, content: lastLines } }));
                }

                // ── Whitelist API for Dashboard ──
            } else if (msg.type === "get_whitelist") {
                ws.send(JSON.stringify({ type: "whitelist", data: blocker.getWhitelist() }));
            } else if (msg.type === "add_whitelist") {
                const added = blocker.addToWhitelist(msg.data.ip);
                ws.send(JSON.stringify({ type: "whitelist_updated", data: { ip: msg.data.ip, added } }));
            } else if (msg.type === "remove_whitelist") {
                const removed = blocker.removeFromWhitelist(msg.data.ip);
                ws.send(JSON.stringify({ type: "whitelist_updated", data: { ip: msg.data.ip, removed } }));

                // ── Block Records API for Dashboard ──
            } else if (msg.type === "get_block_records") {
                ws.send(JSON.stringify({ type: "block_records", data: blocker.getBlockRecords() }));
            } else if (msg.type === "get_security_log") {
                const events = readRecentEvents(msg.data?.count || 50);
                ws.send(JSON.stringify({ type: "security_log", data: events }));

            } else if (msg.type === "TRUNCATE_LOG") {
                const targetPath = msg.path || msg.data?.path;
                if (targetPath && fs.existsSync(targetPath)) {
                    log(`[Agent] 🗑️ Truncating large log file: ${targetPath}`);
                    fs.truncateSync(targetPath, 0);
                    if (watcher.add(targetPath)) tailAndWatch(targetPath);
                    ws.send(JSON.stringify({ type: "command_result", success: true, message: "Log truncated." }));
                }
            }
        } catch (e) {
            log(`Error parsing message: ${e}`);
        }
    });

    ws.on("close", () => {
        log("Client disconnected");
        terminal.kill();
    });

    // Identity handshake
    const sysStats = getSystemStats();
    ws.send(JSON.stringify({ type: "identity", data: sysStats }));

    ws.send(JSON.stringify({
        type: "ai_stats",
        data: {
            totalTokens: aiManager.totalTokens,
            totalCost: aiManager.totalCost,
            requestCount: aiManager.requestCount,
            model: aiManager.model || "Gemini 1.5 Flash",
            mode: aiManager.initialized ? 'neural' : 'shield'
        }
    }));
});

// ── State Persistence ────────────────────────────────────────────

const fileOffsets = new Map<string, number>();

const saveState = () => {
    try {
        let state: any = {};
        if (fs.existsSync(STATE_FILE)) {
            try { state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8')); } catch (e) { }
        }
        state.fileOffsets = Object.fromEntries(fileOffsets);
        fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
    } catch (e) { }
};

const loadState = () => {
    if (fs.existsSync(STATE_FILE)) {
        try {
            const state = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
            if (state.fileOffsets) {
                for (const [p, offset] of Object.entries(state.fileOffsets)) {
                    fileOffsets.set(p, offset as number);
                }
                log(`[Agent] Loaded ${fileOffsets.size} log offsets from state.`);
            }
        } catch (e) { }
    }
};

loadState();

const getStartupLines = (): number => {
    if (fs.existsSync(CONFIG_FILE)) {
        try {
            const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
            if (typeof config.STARTUP_READ_LINES === 'number') return config.STARTUP_READ_LINES;
        } catch (e) { }
    }
    return 500;
};

// ── Log Tailing ──────────────────────────────────────────────────

async function tailAndWatch(filePath: string) {
    if (!fs.existsSync(filePath)) return;
    try {
        const stats = fs.statSync(filePath);
        const fileSize = stats.size;
        const existingOffset = fileOffsets.get(filePath);

        if (existingOffset !== undefined) {
            fileOffsets.set(filePath, fileSize);
            return;
        }

        const startupLines = getStartupLines();

        // 1-Week Ignore Feature: Skip reading historic lines if file hasn't been updated in 7 days
        const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
        const isStale = (Date.now() - stats.mtimeMs) > SEVEN_DAYS_MS;

        if (isStale) {
            log(`[Agent] ⏭️ Skipping initial read for ${filePath} (Not updated in > 7 days)`);
            fileOffsets.set(filePath, fileSize);
            saveState();
            return;
        }

        if (startupLines > 0 && fileSize > 0) {
            const ESTIMATED_BYTES_PER_LINE = 200;
            const readSize = Math.min(fileSize, startupLines * ESTIMATED_BYTES_PER_LINE);
            const readStart = fileSize - readSize;

            const buffer = Buffer.alloc(readSize);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buffer, 0, readSize, readStart);
            fs.closeSync(fd);

            const content = buffer.toString('utf-8');
            const allLines = content.split('\n');
            const linesToProcess = allLines.slice(-startupLines);

            if (linesToProcess.length > 0) {
                log(`[Agent] 🔍 Startup Scan: Checking last ${linesToProcess.length} lines of ${filePath}...`);
                for (const line of linesToProcess) {
                    if (line.trim()) await processLogLine(line, filePath);
                }
            }
        }

        fileOffsets.set(filePath, fileSize);
        saveState();
    } catch (e) {
        log(`[Error] Failed to tail file ${filePath}: ${e}`);
    }
}

// ── Event Listeners ──────────────────────────────────────────────

watcher.on("file_changed", async (changedPath) => {
    try {
        const stats = fs.statSync(changedPath);
        const oldOffset = fileOffsets.get(changedPath) || 0;

        if (stats.size < oldOffset) {
            log(`[Agent] 🔄 Log rotated: ${changedPath}`);
            fileOffsets.set(changedPath, 0);
            await tailAndWatch(changedPath);
            return;
        }
        if (stats.size === oldOffset) return;

        let newBytesSize = stats.size - oldOffset;
        const READ_CAP = 10 * 1024 * 1024; // 10MB safety cap
        let readStart = oldOffset;

        if (newBytesSize > READ_CAP) {
            log(`[Agent] ⚠️ Large churn in ${changedPath} (${(newBytesSize / 1024 / 1024).toFixed(2)} MB). Capping read to last 10MB.`);
            newBytesSize = READ_CAP;
            readStart = stats.size - READ_CAP;
        }

        const buffer = Buffer.alloc(newBytesSize);
        const fd = fs.openSync(changedPath, 'r');
        fs.readSync(fd, buffer, 0, newBytesSize, readStart);
        fs.closeSync(fd);

        fileOffsets.set(changedPath, stats.size);
        saveState();

        const content = buffer.toString('utf-8');
        const lines = content.split('\n');
        for (const line of lines) {
            if (line.trim()) await processLogLine(line, changedPath);
        }
    } catch (e) {
        log(`[Error] Error reading new log bytes for ${changedPath}: ${e}`);
    }
});

watcher.on("file_added", async (addedPath) => {
    await tailAndWatch(addedPath);
});

watcher.on("file_too_large", (largePath, size) => {
    const sizeMB = (size / 1024 / 1024).toFixed(2);
    log(`[Agent] ℹ️ Large file detected: ${largePath} (${sizeMB} MB). Tailing end of file only.`);

    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
                type: "alert",
                data: {
                    risk: "MEDIUM",
                    summary: `Log file too large (${sizeMB} MB). Skipped.`,
                    source: largePath, ip: "N/A", action: "Clear Log File",
                    timestamp: new Date().toISOString(),
                    meta: { type: "file_too_large", path: largePath, size }
                }
            }));
        }
    });

    if (cloudClient) {
        cloudClient.sendAlert("LOG_TOO_LARGE", `Log file ${largePath} size limit (${sizeMB} MB).`, { path: largePath, size });
    }
});

// ── Load Config & Start Watching ─────────────────────────────────

if (fs.existsSync(CONFIG_FILE)) {
    const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
    if (config.LOG_PATHS) {
        for (const logPath of config.LOG_PATHS) {
            if (watcher.add(logPath)) tailAndWatch(logPath);
        }
    }
    if (config.WATCH_FILES) {
        for (const watchFile of config.WATCH_FILES) {
            if (watcher.add(watchFile)) tailAndWatch(watchFile);
        }
    }
}

log("[Sentinel] Agent started successfully");
