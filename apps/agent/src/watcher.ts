import chokidar from "chokidar";
import { EventEmitter } from "events";
import { log } from "@sentinel/core";
import path from "path";
import * as fs from "fs";
import * as os from "os";

export class LogWatcher extends EventEmitter {
    private watcher: chokidar.FSWatcher;

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

    private setupListeners() {
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

    public add(path: string): boolean {
        try {
            if (fs.existsSync(path)) {
                const stats = fs.statSync(path);
                const maxSize = 20 * 1024 * 1024; // 20MB
                if (stats.size > maxSize) {
                    log(`[Watcher] ⚠️ Skipping large file (>20MB): ${path}`);
                    this.emit("file_too_large", path, stats.size);
                    return false;
                }
            }
        } catch (e) {
            return false;
        }

        this.watcher.add(path);
        log(`Watching: ${path}`);
        return true;
    }

    public remove(path: string) {
        this.watcher.unwatch(path);
        // log(`Unwatched: ${path}`);
    }

    public getWatchedFiles(): string[] {
        const watched = this.watcher.getWatched();
        const files: string[] = [];
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

    public static discoverFiles(): string[] {
        const safePatterns = [
            // Core System Logs
            "/var/log/syslog",
            "/var/log/auth.log",
            "/var/log/kern.log",
            "/var/log/dmesg",
            "/var/log/dpkg.log",
            "/var/log/ufw.log",
            // Common Web Servers (Default locations)
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/httpd/access_log",
            "/var/log/httpd/error_log",
            // Database
            "/var/log/mysql/error.log",
            "/var/log/redis/redis-server.log",
            // PHP
            "/var/log/php*-fpm.log",
        ];

        const discovered: string[] = [];

        const checkAndAdd = (p: string) => {
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
                    } catch (e) { }
                }
            } else {
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
            } catch (e) { }
        }

        return discovered;
    }
}
