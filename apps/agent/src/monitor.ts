
import { getSystemStats, log, getProcessStats, getDiskHogs } from "@sentinel/core";
import { TelegramNotifier } from "./telegram.js";

export class ResourceMonitor {
    private telegram: TelegramNotifier;
    private checkInterval: NodeJS.Timeout | null = null;

    // Thresholds (Defaults)
    public thresholds = {
        cpu: 95,
        memory: 90,
        disk: 90,
        duration: 60000 // 1 minute
    };

    // State
    private highCpuSince: number | null = null;
    private highMemSince: number | null = null;
    private highDiskSince: number | null = null;

    constructor(telegram: TelegramNotifier) {
        this.telegram = telegram;
    }

    start() {
        if (this.checkInterval) return;
        log("[Monitor] Starting resource monitoring...");
        // Check every 10 seconds
        this.checkInterval = setInterval(() => this.check(), 10000);
    }

    stop() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }
    }

    private async check() {
        try {
            const stats = getSystemStats();
            const now = Date.now();

            // CPU Check
            if (stats.cpuLoad > this.thresholds.cpu) {
                if (!this.highCpuSince) this.highCpuSince = now;
                else if (now - this.highCpuSince > this.thresholds.duration) {
                    await this.triggerAlert('CPU', stats.cpuLoad);
                    this.highCpuSince = null; // Reset after alert to avoid spam (or implement debounce)
                }
            } else {
                this.highCpuSince = null;
            }

            // Memory Check
            if (stats.memoryUsage > this.thresholds.memory) {
                if (!this.highMemSince) this.highMemSince = now;
                else if (now - this.highMemSince > this.thresholds.duration) {
                    await this.triggerAlert('MEMORY', stats.memoryUsage);
                    this.highMemSince = null;
                }
            } else {
                this.highMemSince = null;
            }

            // Disk Check
            if (stats.diskUsage > this.thresholds.disk) {
                if (!this.highDiskSince) this.highDiskSince = now;
                else if (now - this.highDiskSince > this.thresholds.duration) {
                    await this.triggerAlert('DISK', stats.diskUsage);
                    this.highDiskSince = null;
                }
            } else {
                this.highDiskSince = null;
            }

        } catch (e) {
            log(`[Monitor] Error checking resources: ${e}`);
        }
    }

    private async triggerAlert(type: 'CPU' | 'MEMORY' | 'DISK', value: number) {
        log(`[Monitor] 🚨 High ${type} usage detected: ${value}%`);

        let rootCause = "*Analyzing root cause...*";

        if (type === 'CPU') {
            const processes = await getProcessStats('cpu');
            rootCause = `*Top CPU Consumers:*\n` + processes.map(p => `• \`${p}\``).join('\n');
        } else if (type === 'MEMORY') {
            const processes = await getProcessStats('memory');
            rootCause = `*Top Memory Consumers:*\n` + processes.map(p => `• \`${p}\``).join('\n');
        } else if (type === 'DISK') {
            // Check likely culprits: /var/log, /tmp
            const logs = await getDiskHogs('/var/log');
            rootCause = `*Largest Files in /var/log:*\n` + logs.map(f => `• \`${f}\``).join('\n');
        }

        const message = `🚨 **HIGH ${type} ALERT**\n\n` +
            `Usage: **${value}%** (Threshold: ${this.thresholds[type.toLowerCase() as keyof typeof this.thresholds]}%)\n` +
            `Duration: >${this.thresholds.duration / 1000}s\n\n` +
            `${rootCause}`;

        this.telegram.sendMessage(message);
    }
}
