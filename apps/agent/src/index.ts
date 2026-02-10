import "dotenv/config";
import { WebSocketServer, WebSocket } from "ws";
import * as fs from 'fs';
import os from 'os';
import path from 'path';
import { LogWatcher } from "./watcher.js";
import { AIManager } from "./ai.js";
import { log, getSystemStats, CONFIG_FILE } from "@sentinel/core";
import { BanManager } from "./ban.js";
import { TelegramNotifier } from "./telegram.js";
import { HeartbeatService } from "./heartbeat.js";
import { OWASPScanner } from "./rules.js";
import pty from "node-pty";

// Helper to find an available port
const startWebSocketServer = async (startPort: number): Promise<{ wss: WebSocketServer, port: number }> => {
    return new Promise((resolve, reject) => {
        const server = new WebSocketServer({ port: startPort });

        server.on('listening', () => {
            log(`[Sentinel] WebSocket server listening on port ${startPort}`);
            resolve({ wss: server, port: startPort });
        });

        server.on('error', (err: any) => {
            if (err.code === 'EADDRINUSE') {
                log(`[Sentinel] Port ${startPort} is already in use. Trying ${startPort + 1}...`);
                server.close();
                // Avoid infinite recursion with a reasonable limit
                if (startPort > 8100) {
                    reject(new Error("Could not find an available port in range 8081-8100"));
                    return;
                }
                startWebSocketServer(startPort + 1).then(resolve).catch(reject);
            } else {
                reject(err);
            }
        });
    });
};

// Global WebSocket Server (Dynamic Port)
const { wss, port: selectedPort } = await startWebSocketServer(8081);

wss.on('connection', (ws) => {
    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message.toString());
            if (data.type === "TRUNCATE_LOG") {
                const targetPath = data.path;
                if (targetPath && fs.existsSync(targetPath)) {
                    log(`[Agent] 🗑️ Truncating large log file: ${targetPath}`);
                    fs.truncateSync(targetPath, 0);
                    // Force re-add to watcher if it was skipped
                    if (watcher.add(targetPath)) {
                        tailAndWatch(targetPath);
                    }
                    ws.send(JSON.stringify({ type: "command_result", success: true, message: "Log truncated successfully." }));
                }
            }
        } catch (e) {
            log(`[Agent] Failed to handle WS message: ${e}`);
        }
    });
});


// Safety & Warmup Configuration
const args = process.argv.slice(2);
const isSafeMode = args.includes("--safe") || fs.existsSync("/etc/sentinel/SAFE_MODE");
const WARMUP_DELAY_MS = 60000; // 60s
let isWarmingUp = true;

if (isSafeMode) {
    log("[Safety] 🛡️ STARTING IN SAFE MODE: Active enforcement disabled.");
} else {
    log(`[Safety] ⏳ Warming up for ${WARMUP_DELAY_MS / 1000}s (Detection Only)...`);
    setTimeout(() => {
        isWarmingUp = false;
        log("[Safety] ✅ Warmup complete. Active Defense engaged.");
    }, WARMUP_DELAY_MS);
}

import { ResourceMonitor } from "./monitor.js";
import { CloudClient } from "./cloud.js";

// Initialize Components
const watcher = new LogWatcher();
const aiManager = new AIManager();
const banManager = new BanManager();
const telegram = new TelegramNotifier(banManager);
const heartbeat = new HeartbeatService(wss);
const monitor = new ResourceMonitor(telegram);

// Cloud Client Setup
const cloudUrl = process.env.SENTINEL_CLOUD_URL;
const agentKey = process.env.SENTINEL_AGENT_KEY;

let cloudClient: CloudClient | null = null;

if (cloudUrl && agentKey) {
    log(`[Cloud] Configuration found. Initializing Cloud Client...`);
    cloudClient = new CloudClient(cloudUrl, agentKey, selectedPort);

    cloudClient.connect().then(connected => {
        if (connected && cloudClient) {
            log("[Cloud] Agent acts as a satellite node.");
            const activeCloudClient = cloudClient; // Closure safety

            activeCloudClient.setCommandCallback(async (cmd) => {
                if (cmd.type === "BAN_IP") {
                    const ip = cmd.payload ? JSON.parse(cmd.payload).ip : null;
                    if (ip) {
                        await banManager.banIP(ip);
                        telegram.notifyBan(ip, "via Cloud Dashboard");
                        return { success: true };
                    }
                } else if (cmd.type === "UNBAN_IP") {
                    const ip = cmd.payload ? JSON.parse(cmd.payload).ip : null;
                    if (ip) {
                        await banManager.unbanIP(ip);
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
                if (data.thresholds) {
                    monitor.updateConfig(data.thresholds);
                }
                if (data.aiConfig) {
                    aiManager.updateConfig({
                        provider: data.aiConfig.provider,
                        geminiKey: data.aiConfig.geminiKey,
                        openaiKey: data.aiConfig.openaiKey,
                        zhipuKey: data.aiConfig.zhipuKey,
                        model: data.aiConfig.model
                    });
                }
                // Sync cloud file status to local watcher
                if (data.files) {
                    for (const file of data.files) {
                        if (file.enabled) {
                            watcher.add(file.path);
                        } else {
                            watcher.remove(file.path);
                        }
                    }
                }
            });
        }
    });
}

// Register Telegram Commands
telegram.onCommand("status", async () => {
    const stats = await getSystemStats();
    const bannedCount = banManager.getBannedIPs().length;
    const msg = `🖥️ *Server Status*\n\n` +
        `*CPUs:* ${stats.cpus}\n` +
        `*CPU Load:* ${stats.cpu.load}%\n` +
        `*Memory:* ${stats.memory.usagePercent}%\n` +
        `*Storage:* ${stats.disk.usagePercent}%\n` +
        `*Uptime:* ${Math.floor(stats.uptime / 3600)}h ${Math.floor((stats.uptime % 3600) / 60)}m\n` +
        `*Banned IPs:* ${bannedCount}\n` +
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
    const banned = banManager.getBannedIPs();
    if (banned.length === 0) {
        telegram.sendMessage("✅ *No IPs currently banned.*");
        return;
    }
    const msg = `🚫 *Banned IPs (${banned.length})*\n\n` + banned.map(ip => `• \`${ip}\``).join("\n");
    telegram.sendMessage(msg);
});

telegram.onCommand("watch", (msg) => {
    const args = msg.text?.split(" ") || [];
    const action = args[1]; // add, remove, list
    const path = args[2];

    if (!action || action === "list") {
        const files = watcher.getWatchedFiles();
        if (files.length === 0) telegram.sendMessage("📂 *No files currently watched.*");
        else telegram.sendMessage(`📂 *Watched Files:*\n` + files.map(f => `• \`${f}\``).join("\n"));
        return;
    }

    if (!path) {
        telegram.sendMessage("⚠️ Usage: `/watch <add|remove> <path>`");
        return;
    }

    if (action === "add") {
        if (!fs.existsSync(path)) {
            telegram.sendMessage(`❌ File not found: \`${path}\``);
            return;
        }
        watcher.add(path);
        telegram.sendMessage(`✅ Added to watchlist: \`${path}\``);
    } else if (action === "remove") {
        watcher.remove(path);
        telegram.sendMessage(`🗑️ Removed from watchlist: \`${path}\``);
    }
});

telegram.onCommand("config", (msg) => {
    const args = msg.text?.split(" ") || [];
    const key = args[1]?.toLowerCase();
    const val = parseInt(args[2]);

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

// Start Monitor
monitor.start();

// Start Heartbeat
heartbeat.start();

wss.on("connection", async (ws) => {
    log("Client connected to Sentinel Agent");

    // Spawn a PTY for the terminal
    const shell = process.env.SHELL || "bash";

    const terminal = (pty as any).spawn(shell, [], {
        name: "xterm-color",
        cols: 80,
        rows: 24,
        cwd: process.env.HOME,
        env: process.env
    });

    const onData = (data: string) => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "terminal", data }));
        }
    };

    terminal.on("data", onData);

    // Handle messages from client
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
                const settings = getSettings(logPath);
                if (enabled !== undefined) settings.enabled = enabled;
                if (sampleRate !== undefined) settings.sampleRate = sampleRate;
                if (filterHttp !== undefined) settings.filterHttp = filterHttp;

                if (settings.enabled) {
                    watcher.add(logPath);
                } else {
                    watcher.remove(logPath);
                }

                ws.send(JSON.stringify({ type: "options_updated", data: { path: logPath, settings } }));
            } else if (msg.type === "read_log_file") {
                const { path: logPath, lines } = msg.data;
                if (fs.existsSync(logPath)) {
                    const content = fs.readFileSync(logPath, 'utf-8');
                    const allLines = content.split('\n');
                    const lastLines = allLines.slice(-(lines || 100)).join('\n');
                    ws.send(JSON.stringify({ type: "log_content", data: { path: logPath, content: lastLines } }));
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

    // Send immediate identity handshake
    const sysStats = getSystemStats();
    ws.send(JSON.stringify({
        type: "identity",
        data: sysStats
    }));

    // Send current AI stats
    ws.send(JSON.stringify({
        type: "ai_stats",
        data: {
            totalTokens: aiManager.totalTokens,
            totalCost: aiManager.totalCost,
            requestCount: aiManager.requestCount,
            model: "Gemini 1.5 Flash"
        }
    }));
});

// Log settings and state
const logSettings = new Map<string, {
    enabled: boolean,
    sampleRate: number,
    lineCount: number,
    filterHttp: boolean
}>();

const getSettings = (path: string) => {
    if (!logSettings.has(path)) {
        logSettings.set(path, { enabled: true, sampleRate: 1, lineCount: 0, filterHttp: false });
    }
    return logSettings.get(path)!;
};

const handleLogLine = async (line: string, path: string) => {
    try {
        const settings = getSettings(path);
        if (!settings.enabled) return;

        const lastLine = line.trim();
        if (!lastLine) return;

        // 1. Sampling Check
        settings.lineCount++;
        if (settings.sampleRate > 1 && settings.lineCount % settings.sampleRate !== 0) {
            return;
        }

        // 2. HTTP Method Filtering (POST, OPTIONS, GET with params)
        if (settings.filterHttp) {
            const httpPattern = /(POST|OPTIONS|GET.*?\?.*=)/i;
            if (!httpPattern.test(lastLine)) {
                return;
            }
        }

        // 3. SPECIAL HANDLING: OWASP Local Rules (Priority 1)
        let result = null;
        let isLocalMatch = false;

        const owaspMatches = OWASPScanner.scan(lastLine);
        if (owaspMatches.length > 0) {
            isLocalMatch = true;

            // Prioritize highest risk
            const prioritizedMatch = owaspMatches.reduce((prev, curr) => {
                const risks: Record<string, number> = { "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3 };
                return (risks[curr.risk] || 0) > (risks[prev.risk] || 0) ? curr : prev;
            }, owaspMatches[0]);

            // Extract IP if possible
            const ipMatch = lastLine.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
            const ip = ipMatch ? ipMatch[0] : undefined;

            result = {
                risk: prioritizedMatch.risk,
                summary: `[OWASP ${prioritizedMatch.category}] ${prioritizedMatch.summary}`,
                ip: ip,
                action: prioritizedMatch.action,
                immediate: prioritizedMatch.immediate, // Carry the flag (CRITICAL/HIGH are immediate)
                tokens: 0,
                usage: { totalTokens: aiManager.totalTokens, totalCost: aiManager.totalCost, requestCount: aiManager.requestCount },
                allMatches: owaspMatches,
                cves: owaspMatches.flatMap(m => m.cve || [])
            };
            log(`[Defense] 🛡️ OWASP Match: ${prioritizedMatch.category} detected locally (Shield Mode).`);

        } else if (path.endsWith("auth.log") || path.endsWith("secure")) {
            const authFailPattern = /failed|failure|invalid user|authentication error|refused|disconnect/i;
            if (authFailPattern.test(lastLine)) {
                const ipMatch = lastLine.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
                const ip = ipMatch ? ipMatch[0] : undefined;

                result = {
                    risk: "HIGH",
                    summary: "Detected repeated authentication failure (Local Rule)",
                    ip: ip,
                    action: "Ban IP if repeated",
                    tokens: 0,
                    usage: { totalTokens: aiManager.totalTokens, totalCost: aiManager.totalCost, requestCount: aiManager.requestCount }
                };
            }
        } else {
            // Normal AI Analysis for other logs (Secondary Verification / Discovery)
            result = await aiManager.analyze(lastLine);
        }

        if (result) {
            // Broadcast updated AI stats
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify({
                        type: "ai_stats",
                        data: {
                            totalTokens: aiManager.totalTokens,
                            totalCost: aiManager.totalCost,
                            requestCount: aiManager.requestCount,
                            model: aiManager.model
                        }
                    }));
                }
            });

            // Report tokens to Cloud
            if (cloudClient && result.tokens) {
                cloudClient.addTokens(result.tokens);
            }

            if (result.risk !== "SAFE" && result.risk !== "LOW") {
                log(`[AI ALERT] ${result.risk} on ${path}: ${result.summary}`);

                // Send initial alert
                const alertData = { ...result, timestamp: new Date().toISOString(), source: path };
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify({
                            type: "alert",
                            data: alertData
                        }));
                    }
                });

                if (result.risk === "CRITICAL" || result.risk === "HIGH" || result.risk === "MEDIUM") {
                    telegram.sendAlert(result.risk, `${result.summary} (Source: ${path})`, result.ip);
                }

                // Execute Defense
                if (result.ip && (result.risk === "CRITICAL" || result.risk === "HIGH" || result.risk === "MEDIUM")) {

                    // --- GLOBAL SAFETY CHECK ---
                    if (isSafeMode) {
                        log(`[Safety] 🛡️ SAFE MODE: Suppressed defense against ${result.ip} (Risk: ${result.risk})`);
                        result.action = "Monitor Only (Safe Mode)";
                        return; // EXIT DEFENSE BLOCK
                    }
                    if (isWarmingUp) {
                        log(`[Safety] ⏳ WARMUP: Suppressed defense against ${result.ip} (Risk: ${result.risk})`);
                        result.action = "Monitor Only (Warmup)";
                        return; // EXIT DEFENSE BLOCK
                    }
                    // ---------------------------

                    if ((result as any).immediate) {
                        const isCritical = result.risk === "CRITICAL";
                        log(`[Active Defense] 🔥 ${isCritical ? 'CRITICAL' : 'IMMEDIATE'} BAN TRIGGERED for IP ${result.ip}`);
                        await banManager.banIP(result.ip, result.summary);
                        telegram.notifyBan(result.ip, result.summary);
                        if (cloudClient) {
                            cloudClient.sendAlert("IP_BANNED", `IP ${result.ip} banned ${isCritical ? 'permanently (CRITICAL)' : 'immediately'} (Shield Mode).`, { ip: result.ip, reason: result.summary, risk: result.risk });
                        }
                    } else {
                        const strikes = banManager.addStrike(result.ip);
                        if (strikes >= banManager.MAX_STRIKES) {
                            await banManager.banIP(result.ip);
                            telegram.notifyBan(result.ip, "has exceeded strike limit.");
                            if (cloudClient) {
                                cloudClient.sendAlert("IP_BANNED", `IP ${result.ip} banned after exceeding strike limit.`, { ip: result.ip, reason: "Excessive suspicious activity" });
                            }
                        }
                    }
                }

                // Background Forensic Enrichment (The "Super Power")
                if (isLocalMatch && aiManager.initialized) {
                    (async () => {
                        log(`[AI] ⚡ Initiating forensic enrichment for local match...`);
                        const enriched = await aiManager.enrichAnalysis(lastLine, result);
                        if (enriched.isEnriched) {
                            log(`[AI] 🧠 Forensics complete: ${enriched.forensics.target}`);
                            // Broadcast update to dashboard
                            wss.clients.forEach(client => {
                                if (client.readyState === WebSocket.OPEN) {
                                    client.send(JSON.stringify({
                                        type: "alert_update",
                                        data: { ...enriched, timestamp: alertData.timestamp, source: path }
                                    }));
                                }
                            });
                        }
                    })();
                }
            }
        }

        // Always notify about history updates
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({
                    type: "history_update"
                }));
            }
        });
    } catch (e) {
        log(`[Error] Failed to handle log line: ${e}`);
    }
};

// Offset tracking for incremental reading
const fileOffsets = new Map<string, number>();

const tailAndWatch = async (path: string) => {
    if (!fs.existsSync(path)) return;
    try {
        const stats = fs.statSync(path);
        fileOffsets.set(path, stats.size);

        // Read last 50 lines (Rough estimate: 10KB usually covers it)
        const bufferSize = Math.min(stats.size, 10 * 1024);
        if (bufferSize > 0) {
            const buffer = Buffer.alloc(bufferSize);
            const fd = fs.openSync(path, 'r');
            fs.readSync(fd, buffer, 0, bufferSize, stats.size - bufferSize);
            fs.closeSync(fd);

            const content = buffer.toString('utf-8');
            const lines = content.split('\n').filter(l => l.trim().length > 0);
            const last50 = lines.slice(-50);

            if (last50.length > 0) {
                log(`[Agent] 🔍 Initial scan: Processing last ${last50.length} lines for ${path}`);
                for (const line of last50) {
                    await handleLogLine(line, path);
                }
            }
        }
    } catch (e) {
        log(`[Error] Failed to tail file ${path}: ${e}`);
    }
};

// Event Listeners
watcher.on("file_changed", async (path) => {
    try {
        const stats = fs.statSync(path);
        const oldOffset = fileOffsets.get(path) || 0;

        if (stats.size < oldOffset) {
            // File was truncated or rotated
            log(`[Agent] 🔄 Log rotated: ${path}`);
            fileOffsets.set(path, 0);
            await tailAndWatch(path);
            return;
        }

        if (stats.size === oldOffset) return;

        const newBytesSize = stats.size - oldOffset;
        const buffer = Buffer.alloc(newBytesSize);
        const fd = fs.openSync(path, 'r');
        fs.readSync(fd, buffer, 0, newBytesSize, oldOffset);
        fs.closeSync(fd);

        fileOffsets.set(path, stats.size);

        const content = buffer.toString('utf-8');
        const lines = content.split('\n');

        for (const line of lines) {
            if (line.trim()) {
                await handleLogLine(line, path);
            }
        }
    } catch (e) {
        log(`[Error] Error reading new log bytes for ${path}: ${e}`);
    }
});

watcher.on("file_added", async (path) => {
    await tailAndWatch(path);
});

watcher.on("file_too_large", (path, size) => {
    const sizeMB = (size / 1024 / 1024).toFixed(2);
    log(`[Agent] ⚠️ Large file detected: ${path} (${sizeMB} MB). notifying dashboard.`);

    const alertData = {
        risk: "MEDIUM",
        summary: `Log file too large (${sizeMB} MB). Skipped to prevent instability.`,
        source: path,
        ip: "N/A",
        action: "Clear Log File", // Hint to frontend
        timestamp: new Date().toISOString(),
        meta: { type: "file_too_large", path: path, size: size }
    };

    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
                type: "alert",
                data: alertData
            }));
        }
    });

    if (cloudClient) {
        cloudClient.sendAlert("LOG_TOO_LARGE", `Log file ${path} matches size limit (${sizeMB} MB).`, { path, size });
    }
});

// Load config and watch files
const configPath = CONFIG_FILE;

if (fs.existsSync(configPath)) {
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    if (config.LOG_PATHS) {
        for (const logPath of config.LOG_PATHS) {
            if (watcher.add(logPath)) {
                tailAndWatch(logPath);
            }
        }
    }
    if (config.WATCH_FILES) {
        for (const watchFile of config.WATCH_FILES) {
            if (watcher.add(watchFile)) {
                tailAndWatch(watchFile);
            }
        }
    }
}

log("[Sentinel] Agent started successfully");
