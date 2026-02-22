/**
 * Web Server Deny Manager — Block IPs via Nginx/Apache deny rules
 *
 * Fallback blocking method when behind Cloudflare but without CF API keys.
 * Since iptables can't block real client IPs behind a reverse proxy,
 * this module writes deny rules that the web server enforces at the
 * application layer (after real_ip resolution).
 *
 * Supports:
 *  - Nginx: writes `deny <ip>;` rules to an include file
 *  - Apache: writes `Require not ip <ip>` rules to a conf file
 */

import { exec, execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { log } from '@sentinel/core';

export type WebServerType = 'nginx' | 'apache' | null;

// ── Detect installed web server ──────────────────────────────────

export function detectWebServer(): WebServerType {
    try {

        // Check Nginx first (more common with Cloudflare setups)
        try {
            execSync('command -v nginx', { stdio: 'pipe' });
            return 'nginx';
        } catch { /* not found */ }

        // Fallback to absolute paths for Nginx
        if (fs.existsSync('/usr/sbin/nginx') || fs.existsSync('/usr/local/nginx/sbin/nginx')) {
            return 'nginx';
        }

        // Check Apache
        try {
            execSync('command -v apache2', { stdio: 'pipe' });
            return 'apache';
        } catch { /* not found */ }

        // Fallback to absolute paths for Apache
        if (fs.existsSync('/usr/sbin/apache2') || fs.existsSync('/usr/sbin/httpd')) {
            return 'apache';
        }

        return null;
    } catch {
        return null;
    }
}

// ── Deny file paths ──────────────────────────────────────────────

function getNginxDenyPath(): string {
    if (fs.existsSync('/etc/nginx/conf.d')) return '/etc/nginx/conf.d/sentinel-deny.conf';
    if (fs.existsSync('/etc/nginx/snippets')) return '/etc/nginx/snippets/sentinel-deny.conf';
    return '/etc/nginx/conf.d/sentinel-deny.conf'; // default
}

function getApacheDenyPath(): string {
    if (fs.existsSync('/etc/apache2/conf-available')) return '/etc/apache2/conf-available/sentinel-deny.conf';
    if (fs.existsSync('/etc/httpd/conf.d')) return '/etc/httpd/conf.d/sentinel-deny.conf';
    return '/etc/apache2/conf-available/sentinel-deny.conf'; // default
}

// ── File header templates ────────────────────────────────────────

const NGINX_HEADER = `# ─────────────────────────────────────────────────────────────
# SentinelAI — Dynamic IP Deny List (Nginx)
# Auto-managed by SentinelAI agent. DO NOT EDIT MANUALLY.
#
# Include this file in your server {} blocks:
#   include /path/to/sentinel-deny.conf;
#
# The agent will reload Nginx after changes.
# ─────────────────────────────────────────────────────────────
`;

const APACHE_HEADER = `# ─────────────────────────────────────────────────────────────
# SentinelAI — Dynamic IP Deny List (Apache)
# Auto-managed by SentinelAI agent. DO NOT EDIT MANUALLY.
#
# Enable with: a2enconf sentinel-deny
# The agent will reload Apache after changes.
# ─────────────────────────────────────────────────────────────
<RequireAll>
    Require all granted
`;

const APACHE_FOOTER = `</RequireAll>
`;

// ── Web Server Deny Manager ──────────────────────────────────────

export class WebServerDenyManager {
    private serverType: WebServerType;
    private denyFilePath: string;
    private deniedIPs: Set<string> = new Set();

    constructor(serverType: WebServerType) {
        this.serverType = serverType;

        if (serverType === 'nginx') {
            this.denyFilePath = getNginxDenyPath();
        } else if (serverType === 'apache') {
            this.denyFilePath = getApacheDenyPath();
        } else {
            this.denyFilePath = '';
        }

        // Load existing deny list
        this.loadExisting();

        if (this.serverType) {
            log(`[WebDeny] Initialized for ${this.serverType}. Deny file: ${this.denyFilePath}`);
            log(`[WebDeny] ${this.deniedIPs.size} existing deny rules loaded.`);
        }
    }

    get type(): WebServerType { return this.serverType; }

    /**
     * Add an IP to the deny list and reload the web server.
     */
    async addDeny(ip: string): Promise<boolean> {
        if (!this.serverType) {
            log('[WebDeny] ⚠️ No web server detected, cannot add deny rule.');
            return false;
        }

        if (this.deniedIPs.has(ip)) {
            log(`[WebDeny] ℹ️ ${ip} already in deny list.`);
            return true;
        }

        this.deniedIPs.add(ip);
        this.writeDenyFile();
        await this.reloadWebServer();

        log(`[WebDeny] ✅ Denied ${ip} via ${this.serverType}`);
        return true;
    }

    /**
     * Remove an IP from the deny list and reload the web server.
     */
    async removeDeny(ip: string): Promise<boolean> {
        if (!this.serverType) return false;

        if (!this.deniedIPs.has(ip)) {
            log(`[WebDeny] ℹ️ ${ip} not in deny list.`);
            return false;
        }

        this.deniedIPs.delete(ip);
        this.writeDenyFile();
        await this.reloadWebServer();

        log(`[WebDeny] ✅ Removed deny for ${ip} from ${this.serverType}`);
        return true;
    }

    /**
     * Get all currently denied IPs.
     */
    getDeniedIPs(): string[] {
        return [...this.deniedIPs];
    }

    // ── Internal ─────────────────────────────────────────────────

    private loadExisting(): void {
        if (!this.denyFilePath || !fs.existsSync(this.denyFilePath)) return;

        try {
            const content = fs.readFileSync(this.denyFilePath, 'utf-8');

            if (this.serverType === 'nginx') {
                // Parse: deny 1.2.3.4;
                const matches = content.matchAll(/^deny\s+(\d{1,3}(?:\.\d{1,3}){3});/gm);
                for (const m of matches) {
                    this.deniedIPs.add(m[1]);
                }
            } else if (this.serverType === 'apache') {
                // Parse: Require not ip 1.2.3.4
                const matches = content.matchAll(/Require\s+not\s+ip\s+(\d{1,3}(?:\.\d{1,3}){3})/gm);
                for (const m of matches) {
                    this.deniedIPs.add(m[1]);
                }
            }
        } catch (e) {
            log(`[WebDeny] ⚠️ Error loading existing deny file: ${e}`);
        }
    }

    private writeDenyFile(): void {
        if (!this.denyFilePath) return;

        try {
            const dir = path.dirname(this.denyFilePath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

            let content: string;

            if (this.serverType === 'nginx') {
                content = NGINX_HEADER;
                for (const ip of this.deniedIPs) {
                    content += `deny ${ip};\n`;
                }
            } else {
                // Apache
                content = APACHE_HEADER;
                for (const ip of this.deniedIPs) {
                    content += `    Require not ip ${ip}\n`;
                }
                content += APACHE_FOOTER;
            }

            fs.writeFileSync(this.denyFilePath, content);
        } catch (e) {
            log(`[WebDeny] ❌ Error writing deny file: ${e}`);
        }
    }

    private reloadWebServer(): Promise<void> {
        return new Promise((resolve) => {
            if (!this.serverType) { resolve(); return; }

            const cmd = this.serverType === 'nginx'
                ? 'nginx -t 2>/dev/null && nginx -s reload'
                : '(command -v apache2 &>/dev/null && apache2 -t 2>/dev/null && apachectl graceful) || (command -v httpd &>/dev/null && httpd -t 2>/dev/null && httpd -k graceful)';

            exec(cmd, (error) => {
                if (error) {
                    log(`[WebDeny] ⚠️ Web server reload failed: ${error.message}`);
                    log(`[WebDeny] ⚠️ The deny file was written but the server needs manual reload.`);
                }
                resolve();
            });
        });
    }
}
