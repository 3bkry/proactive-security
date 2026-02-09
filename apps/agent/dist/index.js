import { WebSocketServer, WebSocket } from "ws";
import * as fs from 'fs';
import { LogWatcher } from "./watcher.js";
import { AIManager } from "./ai.js";
import { log, getSystemStats, CONFIG_FILE } from "@sentinel/core";
import { BanManager } from "./ban.js";
import { TelegramNotifier } from "./telegram.js";
import { HeartbeatService } from "./heartbeat.js";
import pty from "node-pty";
// Global WebSocket Server
const wss = new WebSocketServer({ port: 8081 });
// Initialize Components
const watcher = new LogWatcher();
const aiManager = new AIManager();
const banManager = new BanManager();
const telegram = new TelegramNotifier(banManager);
const heartbeat = new HeartbeatService(wss);
// Register Telegram Commands
telegram.onCommand("status", async () => {
    const stats = await getSystemStats();
    const bannedCount = banManager.getBannedIPs().length;
    const msg = `🖥️ *Server Status*\n\n` +
        `*CPUs:* ${stats.cpus}\n` +
        `*Memory:* ${stats.memoryUsage}%\n` +
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
// Start Heartbeat
heartbeat.start();
wss.on("connection", async (ws) => {
    log("Client connected to Sentinel Agent");
    // Spawn a PTY for the terminal
    const shell = process.env.SHELL || "bash";
    const terminal = pty.spawn(shell, [], {
        name: "xterm-color",
        cols: 80,
        rows: 24,
        cwd: process.env.HOME,
        env: process.env
    });
    const onData = (data) => {
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
            }
            else if (msg.type === "resize") {
                terminal.resize(msg.cols, msg.rows);
            }
            else if (msg.type === "get_watched_files") {
                const files = watcher.getWatchedFiles().map(f => ({
                    path: f,
                    stats: fs.existsSync(f) ? fs.statSync(f) : null,
                    settings: getSettings(f)
                }));
                ws.send(JSON.stringify({ type: "watched_files", data: files }));
            }
            else if (msg.type === "get_ai_history") {
                ws.send(JSON.stringify({ type: "ai_history", data: aiManager.history }));
            }
            else if (msg.type === "get_ai_prompt") {
                ws.send(JSON.stringify({ type: "ai_prompt", data: aiManager.promptTemplate }));
            }
            else if (msg.type === "update_ai_prompt") {
                aiManager.promptTemplate = msg.data;
                log("[AI] Prompt template updated");
                ws.send(JSON.stringify({ type: "prompt_updated", data: aiManager.promptTemplate }));
            }
            else if (msg.type === "discover_logs") {
                const discovered = LogWatcher.discoverFiles().map(f => ({
                    path: f,
                    stats: fs.existsSync(f) ? fs.statSync(f) : null,
                    watched: watcher.getWatchedFiles().includes(f)
                }));
                ws.send(JSON.stringify({ type: "discovered_files", data: discovered }));
            }
            else if (msg.type === "update_log_options") {
                const { path: logPath, enabled, sampleRate, filterHttp } = msg.data;
                const settings = getSettings(logPath);
                if (enabled !== undefined)
                    settings.enabled = enabled;
                if (sampleRate !== undefined)
                    settings.sampleRate = sampleRate;
                if (filterHttp !== undefined)
                    settings.filterHttp = filterHttp;
                if (settings.enabled) {
                    watcher.add(logPath);
                }
                else {
                    watcher.remove(logPath);
                }
                ws.send(JSON.stringify({ type: "options_updated", data: { path: logPath, settings } }));
            }
            else if (msg.type === "read_log_file") {
                const { path: logPath, lines } = msg.data;
                if (fs.existsSync(logPath)) {
                    const content = fs.readFileSync(logPath, 'utf-8');
                    const allLines = content.split('\n');
                    const lastLines = allLines.slice(-(lines || 100)).join('\n');
                    ws.send(JSON.stringify({ type: "log_content", data: { path: logPath, content: lastLines } }));
                }
            }
        }
        catch (e) {
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
const logSettings = new Map();
const getSettings = (path) => {
    if (!logSettings.has(path)) {
        logSettings.set(path, { enabled: true, sampleRate: 1, lineCount: 0, filterHttp: false });
    }
    return logSettings.get(path);
};
// Event Listeners
watcher.on("file_changed", async (path) => {
    try {
        const settings = getSettings(path);
        if (!settings.enabled)
            return;
        const content = fs.readFileSync(path, 'utf-8');
        const lines = content.trim().split('\n');
        const lastLine = lines[lines.length - 1];
        if (!lastLine)
            return;
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
    }
    catch (e) {
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
//# sourceMappingURL=index.js.map