import { log, BANNED_IPS_FILE } from "@sentinel/core";
import { exec } from "child_process";
import * as fs from 'fs';
export class BanManager {
    strikes = new Map();
    bannedIPs = new Map();
    MAX_STRIKES = 5;
    DB_PATH = BANNED_IPS_FILE;
    BAN_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 Days
    constructor() {
        this.loadBannedIPs();
        // Run cleanup every hour
        setInterval(() => this.cleanupExpiredBans(), 60 * 60 * 1000);
    }
    loadBannedIPs() {
        if (fs.existsSync(this.DB_PATH)) {
            try {
                const data = JSON.parse(fs.readFileSync(this.DB_PATH, 'utf-8'));
                data.forEach((entry) => {
                    this.bannedIPs.set(entry.ip, entry);
                    // Re-apply ban on startup (persistence)
                    this.executeBan(entry.ip);
                });
            }
            catch (e) {
                log(`[Defense] Failed to load banned IPs: ${e}`);
            }
        }
    }
    saveBannedIPs() {
        try {
            fs.writeFileSync(this.DB_PATH, JSON.stringify(Array.from(this.bannedIPs.values()), null, 2));
        }
        catch (e) {
            log(`[Defense] Failed to save banned IPs: ${e}`);
        }
    }
    addStrike(ip) {
        if (this.bannedIPs.has(ip))
            return this.MAX_STRIKES;
        const count = (this.strikes.get(ip) || 0) + 1;
        this.strikes.set(ip, count);
        log(`[Defense] IP ${ip} strike ${count}/${this.MAX_STRIKES}`);
        return count;
    }
    isBanned(ip) {
        return this.bannedIPs.has(ip);
    }
    async banIP(ip, reason = "Automated Defense") {
        if (this.bannedIPs.has(ip))
            return true;
        log(`[Defense] 🛡️ Banning IP: ${ip} (Reason: ${reason})`);
        this.executeBan(ip);
        this.bannedIPs.set(ip, {
            ip,
            bannedAt: Date.now(),
            reason
        });
        this.saveBannedIPs();
        return true;
    }
    executeBan(ip) {
        // Block on INPUT chain (Host)
        const cmdInput = `iptables -C INPUT -s ${ip} -j DROP 2>/dev/null || iptables -I INPUT 1 -s ${ip} -j DROP`;
        // Block on DOCKER-USER chain (Containers) - improved security for Docker hosts
        const cmdDocker = `iptables -C DOCKER-USER -s ${ip} -j DROP 2>/dev/null || (iptables -L DOCKER-USER >/dev/null 2>&1 && iptables -I DOCKER-USER 1 -s ${ip} -j DROP)`;
        exec(`${cmdInput} && ${cmdDocker}`, (error) => {
            if (error) {
                // Ignore DOCKER-USER errors if chain doesn't exist, but warn for INPUT
                if (!error.message.includes("DOCKER-USER")) {
                    log(`[Defense] ⚠️ Failed to ban ${ip}: ${error.message}. (Ensure agent runs as root)`);
                }
            }
            else {
                // log(`[Defense] ✅ IP ${ip} blocked.`);
            }
        });
    }
    async unbanIP(ip) {
        if (!this.bannedIPs.has(ip))
            return false;
        log(`[Defense] 🔓 Unbanning IP: ${ip}`);
        const cmdInput = `iptables -D INPUT -s ${ip} -j DROP 2>/dev/null`;
        const cmdDocker = `iptables -D DOCKER-USER -s ${ip} -j DROP 2>/dev/null`;
        exec(`${cmdInput}; ${cmdDocker}`, (error) => {
            if (error) {
                log(`[Defense] ⚠️ Failed to unban ${ip}: ${error.message}`);
            }
            else {
                log(`[Defense] ✅ IP ${ip} unbanned.`);
            }
        });
        this.bannedIPs.delete(ip);
        this.saveBannedIPs();
        return true;
    }
    cleanupExpiredBans() {
        const now = Date.now();
        this.bannedIPs.forEach((entry, ip) => {
            if (now - entry.bannedAt > this.BAN_DURATION_MS) {
                log(`[Defense] Ban expired for ${ip}. Unbanning automatically.`);
                this.unbanIP(ip);
            }
        });
    }
    getBannedIPs() {
        return Array.from(this.bannedIPs.keys());
    }
}
//# sourceMappingURL=ban.js.map