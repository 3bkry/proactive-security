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
    cloudClient = new CloudClient(cloudUrl, agentKey);

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

// Event Listeners
watcher.on("file_changed", async (path) => {
    try {
        const settings = getSettings(path);
        if (!settings.enabled) return;

        const content = fs.readFileSync(path, 'utf-8');
        const lines = content.trim().split('\n');
        const lastLine = lines[lines.length - 1];

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

        const result = await aiManager.analyze(lastLine);

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
                            model: "Gemini 1.5 Flash"
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

                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify({
                            type: "alert",
                            data: { ...result, timestamp: new Date().toISOString(), source: path }
                        }));
                    }
                });

                if (result.risk === "HIGH" || result.risk === "MEDIUM") {
                    telegram.sendAlert(result.risk, `${result.summary} (Source: ${path})`, result.ip);
                }

                if (result.ip && (result.risk === "HIGH" || result.risk === "MEDIUM")) {
                    const strikes = banManager.addStrike(result.ip);
                    log(`[Active Defense] Strike ${strikes}/5 for IP ${result.ip}`);

                    if (strikes >= banManager.MAX_STRIKES) {
                        await banManager.banIP(result.ip);
                        telegram.notifyBan(result.ip, "has exceeded strike limit.");
                        if (cloudClient) {
                            cloudClient.sendAlert("IP_BANNED", `IP ${result.ip} banned after ${banManager.MAX_STRIKES} strikes.`, { ip: result.ip, reason: "Excessive suspicious activity" });
                        }
                    }
                }
            }
        }

        // Always notify about history updates so the AI page can refresh (even on failure/skip)
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({
                    type: "history_update"
                }));
            }
        });
    } catch (e) {
        log(`Error processing file change on ${path}: ${e}`);
    }
});

// Load config and watch files
const configPath = CONFIG_FILE;

if (fs.existsSync(configPath)) {
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    if (config.LOG_PATHS) {
        for (const logPath of config.LOG_PATHS) {
            watcher.add(logPath);
        }
    }
    if (config.WATCH_FILES) {
        for (const watchFile of config.WATCH_FILES) {
            watcher.add(watchFile);
        }
    }
}

log("[Sentinel] Agent started successfully");
