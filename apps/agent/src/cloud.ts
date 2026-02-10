
import axios, { AxiosInstance } from "axios";
import { log, getSystemStats, ServerProfile } from "@sentinel/core";

export class CloudClient {
    private client: AxiosInstance;
    private serverId: string | null = null;
    private pulseInterval: NodeJS.Timeout | null = null;
    private commandCallback: ((cmd: any) => Promise<any>) | null = null;
    private syncCallback: ((data: any) => void) | null = null;
    private pendingTokens: number = 0;

    constructor(
        private cloudUrl: string,
        private agentKey: string
    ) {
        this.client = axios.create({
            baseURL: cloudUrl,
            headers: {
                "Content-Type": "application/json",
                "x-agent-key": agentKey
            },
            timeout: 5000
        });
    }

    async connect(maxRetries = 0): Promise<boolean> {
        let attempts = 0;
        while (maxRetries === 0 || attempts < maxRetries) {
            try {
                attempts++;
                log(`[Cloud] Connecting to ${this.cloudUrl} (Attempt ${attempts})...`);
                const stats = getSystemStats();

                // Initial Registration
                const response = await this.client.post("/api/agent/connect", {
                    hostname: stats.hostname,
                    platform: stats.platform,
                    version: "0.1.0",
                    ip: this.getPublicIP(stats)
                });

                if (response.data.success) {
                    this.serverId = response.data.serverId;
                    log(`[Cloud] Connected! Server ID: ${this.serverId}`);
                    this.startPulse();
                    return true;
                }
            } catch (e: any) {
                log(`[Cloud] Connection failed: ${e.message}`);
                // Wait 10 seconds before retrying
                await new Promise(resolve => setTimeout(resolve, 10000));
            }
        }
        return false;
    }

    setCommandCallback(cb: (cmd: any) => Promise<any>) {
        this.commandCallback = cb;
    }

    private pulseDataGetter: (() => any) | null = null;

    setPulseDataGetter(cb: () => any) {
        this.pulseDataGetter = cb;
    }

    setOnSync(cb: (data: any) => void) {
        this.syncCallback = cb;
    }

    private startPulse() {
        if (this.pulseInterval) clearInterval(this.pulseInterval);

        // Pulse every 10 seconds
        this.pulseInterval = setInterval(async () => {
            const tokens = this.pendingTokens;
            this.pendingTokens = 0; // Reset before calling to avoid concurrent pulse loss

            const extra = this.pulseDataGetter ? this.pulseDataGetter() : {};
            await this.pulse(tokens, extra.files);
        }, 10000);
    }

    addTokens(n: number) {
        this.pendingTokens += n;
    }

    async pulse(tokensUsed: number = 0, files?: any[]) {
        if (!this.serverId) return;

        try {
            const stats = getSystemStats();
            const response = await this.client.post("/api/agent/pulse", {
                serverId: this.serverId,
                tokensUsed,
                stats: {
                    cpu: stats.cpu,
                    memory: stats.memory,
                    disk: stats.disk,
                    uptime: stats.uptime
                },
                files
            });

            if (response.data.commands && Array.isArray(response.data.commands)) {
                for (const cmd of response.data.commands) {
                    log(`[Cloud] Received command: ${cmd.type}`);
                    await this.handleCommand(cmd);
                }
            }
            if (this.syncCallback) {
                this.syncCallback(response.data);
            }
            return response.data;
        } catch (e: any) {
            log(`[Cloud] Pulse failed: ${e.message}`);
            return null;
        }
    }

    private async handleCommand(cmd: any) {
        if (!this.commandCallback) return;

        try {
            const result = await this.commandCallback(cmd);

            // Report result
            await this.client.post(`/api/agent/command/${cmd.id}/result`, {
                status: "COMPLETED",
                result: result
            });
        } catch (e: any) {
            await this.client.post(`/api/agent/command/${cmd.id}/result`, {
                status: "FAILED",
                result: { error: e.message }
            });
        }
    }

    async sendAlert(type: string, message: string, details?: any) {
        if (!this.serverId) return;
        try {
            await this.client.post("/api/agent/alert", {
                serverId: this.serverId,
                type,
                message,
                details
            });
        } catch (e: any) {
            log(`[Cloud] Failed to send alert: ${e.message}`);
        }
    }

    private getPublicIP(stats: ServerProfile): string | undefined {
        // Simple heuristic: first non-internal IPv4
        for (const iface of Object.values(stats.networkInterfaces)) {
            if (!iface) continue;
            for (const addr of iface) {
                if (!addr.internal && addr.family === "IPv4") return addr.address;
            }
        }
        return undefined;
    }
}
