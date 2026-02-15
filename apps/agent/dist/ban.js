import { log, BANNED_IPS_FILE, CONFIG_FILE } from "@sentinel/core";
import { exec } from "child_process";
import * as fs from 'fs';
import * as os from 'os';
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
            return false; // Already banned, skip notification
        // --- SAFETY CHECKS ---
        // 1. Hardcoded Loopback Safety
        if (ip === "127.0.0.1" || ip === "::1" || ip === "0.0.0.0" || ip === "localhost") {
            log(`[Defense] ⚠️ SAFETY: Ignoring ban request for loopback address ${ip}`);
            return false;
        }
        // 2. Dynamic Self-IP Detection
        const nets = os.networkInterfaces();
        for (const name of Object.keys(nets)) {
            for (const net of nets[name] || []) {
                if (net.address === ip) {
                    log(`[Defense] ⚠️ SAFETY: Ignoring ban request for SELF-IP ${ip} (${name})`);
                    return false;
                }
            }
        }
        // 3. User Configured Whitelist
        try {
            if (fs.existsSync(CONFIG_FILE)) {
                // Read fresh config to support dynamic updates
                const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
                if (config.WHITELIST_IPS && Array.isArray(config.WHITELIST_IPS)) {
                    if (config.WHITELIST_IPS.includes(ip)) {
                        log(`[Defense] ⚠️ SAFETY: Ignoring ban request for WHITELISTED IP ${ip}`);
                        return false;
                    }
                }
            }
        }
        catch (e) {
            log(`[Defense] Warning: Failed to check whitelist config: ${e}`);
        }
        // ---------------------
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
        // Enforce Allowlist FIRST (Idempotent)
        // 1. Allow Established Connections
        const allowEst = `iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`;
        // 2. Allow Loopback
        const allowLo = `iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -A INPUT -i lo -j ACCEPT`;
        // 3. Allow SSH (Port 22) - Critical for recovery
        const allowSSH = `iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 22 -j ACCEPT`;
        // Block on INPUT chain (Host)
        const cmdInput = `iptables -C INPUT -s ${ip} -j DROP 2>/dev/null || iptables -I INPUT 1 -s ${ip} -j DROP`;
        // Block on DOCKER-USER chain (Containers) - improved security for Docker hosts
        const cmdDocker = `iptables -C DOCKER-USER -s ${ip} -j DROP 2>/dev/null || (iptables -L DOCKER-USER >/dev/null 2>&1 && iptables -I DOCKER-USER 1 -s ${ip} -j DROP)`;
        exec(cmdInput, (error) => {
            if (error) {
                log(`[Defense] ⚠️ Failed to ban ${ip} on host: ${error.message}. (Ensure agent runs as root)`);
            }
            else {
                exec(`${allowEst} && ${allowLo} && ${allowSSH}`, (safetyErr) => {
                    if (safetyErr)
                        log(`[Defense] ⚠️ Failed to apply safety allowlist: ${safetyErr.message}`);
                });
                // Now try Docker ban (okay if it fails/non-docker host)
                exec(cmdDocker, (dockerError) => {
                    // No need to log success for docker, only errors if not just "chain missing"
                    if (dockerError && !dockerError.message.includes("DOCKER-USER")) {
                        // log(`[Defense] Debug: Docker ban failed (might be non-docker host): ${dockerError.message}`);
                    }
                });
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