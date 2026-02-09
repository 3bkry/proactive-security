
import { log, ServerProfile, getSystemStats } from "@sentinel/core";
import { WebSocketServer, WebSocket } from "ws";

export class HeartbeatService {
    private interval: NodeJS.Timeout | null = null;
    private profile: ServerProfile;
    private wss: WebSocketServer | null = null;

    constructor(wss: WebSocketServer) {
        this.wss = wss;
        this.profile = getSystemStats();
        log(`[Heartbeat] Server Identity: ${this.profile.hostname} (${this.profile.platform} ${this.profile.arch})`);

        // Log Identity on startup
        this.logIdentity();
    }

    start(intervalMs: number = 30000) {
        if (this.interval) return;

        // Send initial pulse immediately
        this.pulse();

        log(`[Heartbeat] Starting heartbeat service (interval: ${intervalMs}ms)`);
        this.interval = setInterval(() => {
            this.pulse();
        }, intervalMs);
    }

    stop() {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
    }

    private logIdentity() {
        // Broadcast identity to all connected clients
        const message = JSON.stringify({
            type: "identity",
            data: this.profile
        });

        this.broadcast(message);
    }

    private pulse() {
        const stats = {
            ...this.profile,
            memory: process.memoryUsage().rss.toString(),
            uptime: process.uptime(),
            timestamp: Date.now()
        };

        const message = JSON.stringify({
            type: "heartbeat",
            data: stats
        });

        this.broadcast(message);
        log(`[Heartbeat] Pulse - Uptime: ${Math.floor(stats.uptime)}s`);
    }

    private broadcast(data: string) {
        if (!this.wss) return;
        this.wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(data);
            }
        });
    }
}
