import chokidar from "chokidar";
import { EventEmitter } from "events";
import { log } from "@sentinel/core";
import path from "path";
import * as fs from "fs";
import * as os from "os";
export class LogWatcher extends EventEmitter {
    watcher;
    constructor() {
        super();
        this.watcher = chokidar.watch([], {
            persistent: true,
            ignoreInitial: true,
            usePolling: true,
            depth: 2, // Hard limit on recursion depth
            ignored: [
                /(^|[\/\\])\../, // Dotfiles
                "**/node_modules/**",
                "**/.git/**",
                "**/.next/**",
                "/proc/**",
                "/sys/**",
                "/dev/**",
                "/run/**",
                "/tmp/**",
                "/var/lib/**",
                "/var/cache/**",
                // Exclude self-logs
                path.join(os.homedir(), ".sentinel/logs/**"),
                path.join(os.homedir(), ".pm2/logs/sentinel-agent*")
            ]
        });
        this.setupListeners();
    }
    setupListeners() {
        this.watcher
            .on("add", (path) => {
            log(`File added: ${path}`);
            this.emit("file_added", path);
        })
            .on("change", (path) => {
            // log(`File changed: ${path}`);
            this.emit("file_changed", path);
        })
            .on("unlink", (path) => {
            log(`File removed: ${path}`);
            this.emit("file_removed", path);
        });
    }
    add(filePath) {
        // Skip error logs — they produce too many false positives
        const basename = path.basename(filePath);
        if (/error[._-]?log/i.test(basename) || basename === 'error_log') {
            log(`[Watcher] ⚠️ Skipping error log (high false-positive rate): ${filePath}`);
            return false;
        }
        try {
            if (fs.existsSync(filePath)) {
                const stats = fs.statSync(filePath);
                const maxSize = 10 * 1024 * 1024; // 10MB (Reduced from 20MB)
                if (stats.size > maxSize) {
                    log(`[Watcher] ⚠️ Skipping large file (>10MB): ${filePath}`);
                    this.emit("file_too_large", filePath, stats.size);
                    return false;
                }
            }
        }
        catch (e) {
            return false;
        }
        this.watcher.add(filePath);
        log(`Watching: ${filePath}`);
        return true;
    }
    remove(filePath) {
        this.watcher.unwatch(filePath);
        // log(`Unwatched: ${filePath}`);
    }
    getWatchedFiles() {
        const watched = this.watcher.getWatched();
        const files = [];
        for (const dir in watched) {
            for (const file of watched[dir]) {
                const fullPath = dir === "." ? file : `${dir}/${file}`;
                if (fs.existsSync(fullPath)) {
                    files.push(fullPath);
                }
            }
        }
        return files;
    }
    static discoverFiles() {
        const safePatterns = [
            // Core System Logs
            "/var/log/syslog",
            "/var/log/auth.log",
            "/var/log/kern.log",
            "/var/log/dmesg",
            "/var/log/dpkg.log",
            "/var/log/ufw.log",
            // Common Web Servers (Access logs only - error logs are too noisy)
            "/var/log/nginx/access.log",
            // "/var/log/nginx/error.log", // Disabled by default
            "/var/log/apache2/access.log",
            // "/var/log/apache2/error.log", // Disabled by default
            "/var/log/httpd/access_log",
            // "/var/log/httpd/error_log", // Disabled by default
            // Database
            // "/var/log/mysql/error.log", // Disabled by default
            // "/var/log/redis/redis-server.log", // Disabled by default
            // PHP
            // "/var/log/php*-fpm.log", 
        ];
        const discovered = [];
        const checkAndAdd = (p) => {
            if (fs.existsSync(p)) {
                discovered.push(p);
            }
        };
        for (const pattern of safePatterns) {
            if (pattern.includes("*")) {
                // Simple wildcard handling for one level (e.g. php*-fpm.log)
                const dir = path.dirname(pattern);
                const filePattern = path.basename(pattern);
                if (fs.existsSync(dir)) {
                    try {
                        const files = fs.readdirSync(dir);
                        for (const f of files) {
                            // Convert glob * to regex .*
                            const regex = new RegExp("^" + filePattern.replace(/\*/g, ".*") + "$");
                            if (regex.test(f)) {
                                discovered.push(path.join(dir, f));
                            }
                        }
                    }
                    catch (e) { }
                }
            }
            else {
                checkAndAdd(pattern);
            }
        }
        // Custom user logs (non-recursive, specific folder)
        const pm2Logs = path.join(os.homedir(), ".pm2/logs");
        if (fs.existsSync(pm2Logs)) {
            try {
                const files = fs.readdirSync(pm2Logs);
                for (const f of files) {
                    // Only .log files, exclude sentinel-agent itself to prevent loops
                    if (f.endsWith(".log") && !f.includes("sentinel-agent")) {
                        discovered.push(path.join(pm2Logs, f));
                    }
                }
            }
            catch (e) { }
        }
        return discovered;
    }
}
//# sourceMappingURL=watcher.js.map