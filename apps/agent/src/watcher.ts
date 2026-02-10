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

    public add(path: string) {
        this.watcher.add(path);
        log(`Watching: ${path}`);
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
        const rootPaths = [
            "/var/log",
            path.join(os.homedir(), ".pm2/logs"),
            "/home/antigravity", // User home for custom logs
        ];

        const discovered: string[] = [];
        const seen = new Set<string>();

        const scan = (dir: string, depth: number = 0) => {
            if (depth > 2) return; // Hard Limit depth to 2
            if (!fs.existsSync(dir)) return;

            // Manual Hard Excludes for Discovery
            if (dir.startsWith("/proc") || dir.startsWith("/sys") || dir.startsWith("/dev") || dir.startsWith("/run") || dir.includes("node_modules") || dir.includes(".next")) return;

            try {
                const stats = fs.statSync(dir);
                if (!stats.isDirectory()) return;

                const items = fs.readdirSync(dir);
                for (const item of items) {
                    const fullPath = path.join(dir, item);
                    try {
                        if (!fs.existsSync(fullPath)) continue;
                        const s = fs.statSync(fullPath);

                        if (s.isDirectory()) {
                            // Only recurse into relevant directories to avoid massive scans
                            const lowerItem = item.toLowerCase();
                            if (depth === 0 ||
                                lowerItem.includes("log") ||
                                lowerItem.includes("nginx") ||
                                lowerItem.includes("apache") ||
                                lowerItem.includes("php") ||
                                lowerItem.includes("mysql") ||
                                lowerItem.includes("redis")) {
                                scan(fullPath, depth + 1);
                            }
                        } else if (s.isFile()) {
                            const lowerFile = item.toLowerCase();

                            // 1. MANDATORY Freshness (30 days)
                            const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
                            if (s.mtimeMs < thirtyDaysAgo) return;

                            // 2. Strict Identification
                            const isCoreLog = lowerFile === "syslog" ||
                                lowerFile === "auth.log" ||
                                lowerFile === "kern.log";

                            // Must end with .log exactly
                            const endsWithLog = lowerFile.endsWith(".log");

                            // 3. Strict Exclusion Filters (Apply to everything)
                            const isCompressed = lowerFile.endsWith(".gz") || lowerFile.endsWith(".zip") || lowerFile.endsWith(".tar");
                            const isRotated = /\.\d+$/.test(lowerFile) || lowerFile.includes(".log.");
                            const isBackup = lowerFile.includes(".bak") || lowerFile.includes(".old") || lowerFile.includes(".backup") || lowerFile.includes("-202");

                            // Combination: Must be Core OR end in .log AND not be filtered
                            if ((isCoreLog || endsWithLog) && !isCompressed && !isRotated && !isBackup && !seen.has(fullPath)) {
                                discovered.push(fullPath);
                                seen.add(fullPath);
                            }
                        }
                    } catch (e) {
                        // Skip unreadable files/dirs
                    }
                }
            } catch (e) {
                // Skip unreadable dirs
            }
        };

        for (const p of rootPaths) {
            scan(p);
        }

        return discovered;
    }
}
