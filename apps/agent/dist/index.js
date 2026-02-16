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
import { WebSocketServer, WebSocket } from "ws";
import * as fs from 'fs';
import { LogWatcher } from "./watcher.js";
import { AIManager } from "./ai.js";
import { log, getSystemStats, CONFIG_FILE, STATE_FILE, } from '@sentinel/core';
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
const startWebSocketServer = async (startPort) => {
    return new Promise((resolve, reject) => {
        const server = new WebSocketServer({ port: startPort });
        server.on('listening', () => {
            log(`[Sentinel] WebSocket server listening on port ${startPort}`);
            resolve({ wss: server, port: startPort });
        });
        server.on('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                log(`[Sentinel] Port ${startPort} in use. Trying ${startPort + 1}...`);
                server.close();
                if (startPort > 8100) {
                    reject(new Error("No available port in 8081-8100"));
                    return;
                }
                startWebSocketServer(startPort + 1).then(resolve).catch(reject);
            }
            else
                reject(err);
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
}
else {
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
let defenseConfig = {};
if (fs.existsSync(CONFIG_FILE)) {
    try {
        const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
        if (config.defense)
            defenseConfig = config.defense;
        if (config.TRUSTED_PROXIES)
            setTrustedProxies(config.TRUSTED_PROXIES);
    }
    catch (e) { /* ok */ }
}
const blocker = new Blocker(defenseConfig, isSafeMode);
const rateLimiter = new RateLimiter(defenseConfig);
const telegram = new TelegramNotifier(blocker); // Blocker has compatible API
const heartbeat = new HeartbeatService(wss);
const monitor = new ResourceMonitor(telegram);
// ── Initialize Cloudflare Ranges ─────────────────────────────────
await initCloudflareRanges();
// ── Initialize Pipeline ──────────────────────────────────────────
// Cloud Client Setup
let cloudUrl = process.env.SENTINEL_CLOUD_URL;
let agentKey = process.env.SENTINEL_AGENT_KEY;
if (fs.existsSync(CONFIG_FILE)) {
    try {
        const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
        if (!cloudUrl && config.SENTINEL_CLOUD_URL)
            cloudUrl = config.SENTINEL_CLOUD_URL;
        if (!agentKey && config.SENTINEL_AGENT_KEY)
            agentKey = config.SENTINEL_AGENT_KEY;
    }
    catch (e) {
        log(`[Config] Failed to read config file: ${e}`);
    }
}
let cloudClient = null;
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
                }
                else if (cmd.type === "UNBAN_IP") {
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
            activeCloudClient.setOnSync((data) => {
                if (data.thresholds)
                    monitor.updateConfig(data.thresholds);
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
                        if (file.enabled)
                            watcher.add(file.path);
                        else
                            watcher.remove(file.path);
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
    aiManager,
    telegram,
    wss,
    cloudClient,
    isSafeMode,
    isWarmingUp,
});
// ── Telegram Commands ────────────────────────────────────────────
telegram.onCommand("status", async () => {
    const stats = await getSystemStats();
    const blockedCount = blocker.getBlockedIPs().length;
    const msg = `🖥️ *Server Status*\n\n` +
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
    const blocked = blocker.getBlockedIPs();
    if (blocked.length === 0) {
        telegram.sendMessage("✅ *No IPs currently blocked.*");
        return;
    }
    const msg = `🚫 *Blocked IPs (${blocked.length})*\n\n` + blocked.map(ip => `• \`${ip}\``).join("\n");
    telegram.sendMessage(msg);
});
telegram.onCommand("whitelist", (msg) => {
    const cmdArgs = msg.text?.split(" ") || [];
    const action = cmdArgs[1]; // add, remove, list
    const ip = cmdArgs[2];
    if (!action || action === "list") {
        const wl = blocker.getWhitelist();
        if (wl.length === 0) {
            telegram.sendMessage("📋 *Whitelist is empty.*");
        }
        else {
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
        }
        else {
            telegram.sendMessage(`ℹ️ \`${ip}\` is already whitelisted.`);
        }
    }
    else if (action === "remove") {
        const removed = blocker.removeFromWhitelist(ip);
        if (removed) {
            telegram.sendMessage(`🗑️ Removed \`${ip}\` from whitelist.`);
        }
        else {
            telegram.sendMessage(`ℹ️ \`${ip}\` was not in the whitelist.`);
        }
    }
});
telegram.onCommand("watch", (msg) => {
    const cmdArgs = msg.text?.split(" ") || [];
    const action = cmdArgs[1];
    const watchPath = cmdArgs[2];
    if (!action || action === "list") {
        const files = watcher.getWatchedFiles();
        if (files.length === 0)
            telegram.sendMessage("📂 *No files currently watched.*");
        else
            telegram.sendMessage(`📂 *Watched Files:*\n` + files.map(f => `• \`${f}\``).join("\n"));
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
    }
    else if (action === "remove") {
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
    if (key === 'cpu')
        monitor.thresholds.cpu = val;
    else if (key === 'memory')
        monitor.thresholds.memory = val;
    else if (key === 'disk')
        monitor.thresholds.disk = val;
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
    const terminal = pty.spawn(shell, [], {
        name: "xterm-color", cols: 80, rows: 24,
        cwd: process.env.HOME, env: process.env
    });
    const onData = (data) => {
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
                const updated = updateSettings(logPath, { enabled, sampleRate, filterHttp });
                if (updated.enabled)
                    watcher.add(logPath);
                else
                    watcher.remove(logPath);
                ws.send(JSON.stringify({ type: "options_updated", data: { path: logPath, settings: updated } }));
            }
            else if (msg.type === "read_log_file") {
                const { path: logPath, lines } = msg.data;
                if (fs.existsSync(logPath)) {
                    const content = fs.readFileSync(logPath, 'utf-8');
                    const allLines = content.split('\n');
                    const lastLines = allLines.slice(-(lines || 100)).join('\n');
                    ws.send(JSON.stringify({ type: "log_content", data: { path: logPath, content: lastLines } }));
                }
                // ── Whitelist API for Dashboard ──
            }
            else if (msg.type === "get_whitelist") {
                ws.send(JSON.stringify({ type: "whitelist", data: blocker.getWhitelist() }));
            }
            else if (msg.type === "add_whitelist") {
                const added = blocker.addToWhitelist(msg.data.ip);
                ws.send(JSON.stringify({ type: "whitelist_updated", data: { ip: msg.data.ip, added } }));
            }
            else if (msg.type === "remove_whitelist") {
                const removed = blocker.removeFromWhitelist(msg.data.ip);
                ws.send(JSON.stringify({ type: "whitelist_updated", data: { ip: msg.data.ip, removed } }));
                // ── Block Records API for Dashboard ──
            }
            else if (msg.type === "get_block_records") {
                ws.send(JSON.stringify({ type: "block_records", data: blocker.getBlockRecords() }));
            }
            else if (msg.type === "get_security_log") {
                const events = readRecentEvents(msg.data?.count || 50);
                ws.send(JSON.stringify({ type: "security_log", data: events }));
            }
            else if (msg.type === "TRUNCATE_LOG") {
                const targetPath = msg.path || msg.data?.path;
                if (targetPath && fs.existsSync(targetPath)) {
                    log(`[Agent] 🗑️ Truncating large log file: ${targetPath}`);
                    fs.truncateSync(targetPath, 0);
                    if (watcher.add(targetPath))
                        tailAndWatch(targetPath);
                    ws.send(JSON.stringify({ type: "command_result", success: true, message: "Log truncated." }));
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
    // Identity handshake
    const sysStats = getSystemStats();
    ws.send(JSON.stringify({ type: "identity", data: sysStats }));
    ws.send(JSON.stringify({
        type: "ai_stats",
        data: {
            totalTokens: aiManager.totalTokens,
            totalCost: aiManager.totalCost,
            requestCount: aiManager.requestCount,
            model: aiManager.model || "Gemini 1.5 Flash"
        }
    }));
});
// ── State Persistence ────────────────────────────────────────────
const fileOffsets = new Map();
const saveState = () => {
    try {
        let state = {};
        if (fs.existsSync(STATE_FILE)) {
            try {
                state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8'));
            }
            catch (e) { }
        }
        state.fileOffsets = Object.fromEntries(fileOffsets);
        fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
    }
    catch (e) { }
};
const loadState = () => {
    if (fs.existsSync(STATE_FILE)) {
        try {
            const state = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
            if (state.fileOffsets) {
                for (const [p, offset] of Object.entries(state.fileOffsets)) {
                    fileOffsets.set(p, offset);
                }
                log(`[Agent] Loaded ${fileOffsets.size} log offsets from state.`);
            }
        }
        catch (e) { }
    }
};
loadState();
const getStartupLines = () => {
    if (fs.existsSync(CONFIG_FILE)) {
        try {
            const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
            if (typeof config.STARTUP_READ_LINES === 'number')
                return config.STARTUP_READ_LINES;
        }
        catch (e) { }
    }
    return 500;
};
// ── Log Tailing ──────────────────────────────────────────────────
async function tailAndWatch(filePath) {
    if (!fs.existsSync(filePath))
        return;
    try {
        const stats = fs.statSync(filePath);
        const fileSize = stats.size;
        const existingOffset = fileOffsets.get(filePath);
        if (existingOffset !== undefined) {
            fileOffsets.set(filePath, fileSize);
            return;
        }
        const startupLines = getStartupLines();
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
                    if (line.trim())
                        await processLogLine(line, filePath);
                }
            }
        }
        fileOffsets.set(filePath, fileSize);
        saveState();
    }
    catch (e) {
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
        if (stats.size === oldOffset)
            return;
        const newBytesSize = stats.size - oldOffset;
        const buffer = Buffer.alloc(newBytesSize);
        const fd = fs.openSync(changedPath, 'r');
        fs.readSync(fd, buffer, 0, newBytesSize, oldOffset);
        fs.closeSync(fd);
        fileOffsets.set(changedPath, stats.size);
        saveState();
        const content = buffer.toString('utf-8');
        const lines = content.split('\n');
        for (const line of lines) {
            if (line.trim())
                await processLogLine(line, changedPath);
        }
    }
    catch (e) {
        log(`[Error] Error reading new log bytes for ${changedPath}: ${e}`);
    }
});
watcher.on("file_added", async (addedPath) => {
    await tailAndWatch(addedPath);
});
watcher.on("file_too_large", (largePath, size) => {
    const sizeMB = (size / 1024 / 1024).toFixed(2);
    log(`[Agent] ⚠️ Large file: ${largePath} (${sizeMB} MB). Skipped.`);
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
            if (watcher.add(logPath))
                tailAndWatch(logPath);
        }
    }
    if (config.WATCH_FILES) {
        for (const watchFile of config.WATCH_FILES) {
            if (watcher.add(watchFile))
                tailAndWatch(watchFile);
        }
    }
}
log("[Sentinel] Agent started successfully");
//# sourceMappingURL=index.js.map