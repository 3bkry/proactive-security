import { log, BANNED_IPS_FILE } from "@sentinel/core";
import { exec } from "child_process";
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

interface BannedIP {
    ip: string;
    bannedAt: number;
    reason: string;
}

export class BanManager {
    private strikes: Map<string, number> = new Map();
    private bannedIPs: Map<string, BannedIP> = new Map();
    public readonly MAX_STRIKES = 5;
    private readonly DB_PATH = BANNED_IPS_FILE;
    private readonly BAN_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 Days

    constructor() {
        this.loadBannedIPs();
        // Run cleanup every hour
        setInterval(() => this.cleanupExpiredBans(), 60 * 60 * 1000);
    }

    private loadBannedIPs() {
        if (fs.existsSync(this.DB_PATH)) {
            try {
                const data = JSON.parse(fs.readFileSync(this.DB_PATH, 'utf-8'));
                data.forEach((entry: BannedIP) => this.bannedIPs.set(entry.ip, entry));
            } catch (e) {
                log(`[Defense] Failed to load banned IPs: ${e}`);
            }
        }
    }

    private saveBannedIPs() {
        try {
            fs.writeFileSync(this.DB_PATH, JSON.stringify(Array.from(this.bannedIPs.values()), null, 2));
        } catch (e) {
            log(`[Defense] Failed to save banned IPs: ${e}`);
        }
    }

    addStrike(ip: string): number {
        if (this.bannedIPs.has(ip)) return this.MAX_STRIKES;

        const count = (this.strikes.get(ip) || 0) + 1;
        this.strikes.set(ip, count);
        log(`[Defense] IP ${ip} strike ${count}/${this.MAX_STRIKES}`);
        return count;
    }

    isBanned(ip: string): boolean {
        return this.bannedIPs.has(ip);
    }

    async banIP(ip: string, reason: string = "Automated Defense"): Promise<boolean> {
        if (this.bannedIPs.has(ip)) return true;

        log(`[Defense] 🛡️ Banning IP: ${ip} (Reason: ${reason})`);

        // Execute real ban
        exec(`sudo iptables -C INPUT -s ${ip} -j DROP 2>/dev/null || sudo iptables -A INPUT -s ${ip} -j DROP`, (error) => {
            if (error) {
                log(`[Defense] ⚠️ Failed to execute iptables rule for ${ip}: ${error.message} (Requires sudo/root)`);
            } else {
                log(`[Defense] ✅ IP ${ip} successfully blocked via iptables.`);
            }
        });

        this.bannedIPs.set(ip, {
            ip,
            bannedAt: Date.now(),
            reason
        });
        this.saveBannedIPs();

        return true;
    }

    async unbanIP(ip: string): Promise<boolean> {
        if (!this.bannedIPs.has(ip)) return false;

        log(`[Defense] 🔓 Unbanning IP: ${ip}`);

        exec(`sudo iptables -D INPUT -s ${ip} -j DROP`, (error) => {
            if (error) {
                log(`[Defense] ⚠️ Failed to remove iptables rule for ${ip}: ${error.message}`);
            } else {
                log(`[Defense] ✅ IP ${ip} unbanned.`);
            }
        });

        this.bannedIPs.delete(ip);
        this.saveBannedIPs();
        return true;
    }

    private cleanupExpiredBans() {
        const now = Date.now();
        this.bannedIPs.forEach((entry, ip) => {
            if (now - entry.bannedAt > this.BAN_DURATION_MS) {
                log(`[Defense] Ban expired for ${ip}. Unbanning automatically.`);
                this.unbanIP(ip);
            }
        });
    }

    getBannedIPs(): string[] {
        return Array.from(this.bannedIPs.keys());
    }
}
