
import TelegramBot from 'node-telegram-bot-api';
import { log, CONFIG_FILE, STATE_FILE } from '@sentinel/core';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { Blocker } from './defense/blocker.js';

export class TelegramNotifier {
    private bot: TelegramBot | null = null;
    private chatId: string | null = null;
    private blocker: Blocker | null = null;

    private sentAlerts = new Map<string, number>();
    private isRateLimited = false;
    private rateLimitResetTime = 0;

    constructor(blocker?: Blocker | any) {
        if (blocker) this.blocker = blocker;
        this.loadState();
        this.initialize();

        // Cleanup old alerts every 10 minutes
        setInterval(() => {
            const now = Date.now();
            let changed = false;
            for (const [key, timestamp] of this.sentAlerts.entries()) {
                if (now - timestamp > 10 * 60 * 1000) {
                    this.sentAlerts.delete(key);
                    changed = true;
                }
            }
            if (changed) this.saveState();
        }, 10 * 60 * 1000);
    }

    private loadState() {
        if (fs.existsSync(STATE_FILE)) {
            try {
                const state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8'));
                if (state.sentAlerts) {
                    this.sentAlerts = new Map(Object.entries(state.sentAlerts));
                    log(`[Telegram] Loaded ${this.sentAlerts.size} alerts from state.`);
                }
            } catch (e) {
                log(`[Telegram] Failed to load state: ${e}`);
            }
        }
    }

    private saveState() {
        try {
            let state: any = {};
            if (fs.existsSync(STATE_FILE)) {
                try {
                    state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8'));
                } catch (e) { }
            }
            state.sentAlerts = Object.fromEntries(this.sentAlerts);
            fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
        } catch (e) {
            log(`[Telegram] Failed to save state: ${e}`);
        }
    }

    private initialize() {
        try {
            if (fs.existsSync(CONFIG_FILE)) {
                const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
                const token = config.TELEGRAM_BOT_TOKEN;
                this.chatId = config.TELEGRAM_CHAT_ID;

                if (token && this.chatId) {
                    // Enable polling to receive button clicks and commands
                    this.bot = new TelegramBot(token, { polling: true });
                    log("[Telegram] Initialized successfully with polling.");

                    this.bot.on('callback_query', async (query) => {
                        const action = query.data;
                        if (!action || !this.blocker) return;

                        if (action.startsWith('ban_')) {
                            const ip = action.split('_')[1];
                            await this.blocker.evaluate({ ip, realIP: ip, proxyIP: null, userAgent: null, endpoint: null, method: null, risk: 'HIGH', reason: 'Manual Ban via Telegram', source: 'telegram', immediate: true });

                            // Acknowledge logic
                            if (query.id) {
                                this.bot?.answerCallbackQuery(query.id, { text: `IP ${ip} Banned!` });
                                const opts: TelegramBot.SendMessageOptions = {
                                    parse_mode: 'Markdown',
                                    reply_markup: {
                                        inline_keyboard: [[{ text: `🔓 Unban ${ip}`, callback_data: `unban_${ip}` }]]
                                    }
                                };
                                this.sendToChat(query.message!.chat.id, `🚫 **IP BANNED MANUALLY:** ${ip}`, opts);
                            }
                        } else if (action.startsWith('unban_')) {
                            const ip = action.split('_')[1];
                            await this.blocker.unblock(ip);

                            if (query.id) {
                                this.bot?.answerCallbackQuery(query.id, { text: `IP ${ip} Unbanned!` });
                                this.sendToChat(query.message!.chat.id, `✅ **IP UNBANNED:** ${ip}`, { parse_mode: 'Markdown' });
                            }
                        }
                    });

                    // Handle standard commands
                    this.bot.onText(/\/help/, (msg) => {
                        if (String(msg.chat.id) !== String(this.chatId)) return;
                        const helpMsg = `🛡️ *SentinelAI Bot Help*\n\n` +
                            `/status - Server resources & security status\n` +
                            `/stats - AI analysis & cost stats\n` +
                            `/banned - List blocked IPs\n` +
                            `/whitelist <add|remove|list> [ip] - Manage IP whitelist\n` +
                            `/watch <add|remove|list> [path] - Manage watched files\n` +
                            `/config <cpu|memory|disk> <val> - Set alert thresholds\n` +
                            `/help - Show this message`;
                        this.sendToChat(msg.chat.id, helpMsg, { parse_mode: 'Markdown' });
                    });
                }
            }
        } catch (e) {
            log(`[Telegram] Initialization failed: ${e}`);
        }
    }

    public onCommand(command: string, handler: (msg: TelegramBot.Message) => void) {
        this.bot?.onText(new RegExp(`^\\/${command}`), (msg) => {
            if (String(msg.chat.id) !== String(this.chatId)) return;
            handler(msg);
        });
    }

    // Levenshtein distance for similarity check
    private getSimilarity(s1: string, s2: string): number {
        const longer = s1.length > s2.length ? s1 : s2;
        const shorter = s1.length > s2.length ? s2 : s1;
        if (longer.length === 0) return 1.0;

        const costs = new Array();
        for (let i = 0; i <= longer.length; i++) {
            let lastValue = i;
            for (let j = 0; j <= shorter.length; j++) {
                if (i == 0) costs[j] = j;
                else {
                    if (j > 0) {
                        let newValue = costs[j - 1];
                        if (longer.charAt(i - 1) != shorter.charAt(j - 1))
                            newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
                        costs[j - 1] = lastValue;
                        lastValue = newValue;
                    }
                }
            }
            if (i > 0) costs[shorter.length] = lastValue;
        }
        return (longer.length - costs[shorter.length]) / longer.length;
    }

    private async _executeSend(chatId: number | string, text: string, options: TelegramBot.SendMessageOptions) {
        if (!this.bot) return;

        // Rate Limit Handling
        if (this.isRateLimited) {
            const waitTime = Math.ceil((this.rateLimitResetTime - Date.now()) / 1000);
            if (waitTime > 0) {
                log(`[Telegram] Rate limited. Dropping message (Retry in ${waitTime}s).`);
                return;
            }
            this.isRateLimited = false;
        }

        try {
            await this.bot.sendMessage(chatId, text, options);
        } catch (e: any) {
            if (e.response && e.response.statusCode === 429) {
                const retryAfter = e.response.body?.parameters?.retry_after || 4;
                this.isRateLimited = true;
                this.rateLimitResetTime = Date.now() + (retryAfter * 1000);
                log(`[Telegram] ⚠️ 429 Too Many Requests. Pausing for ${retryAfter}s.`);
            } else {
                log(`[Telegram] Failed to send message: ${e}`);
            }
        }
    }

    // Public method for sending to the configured admin chat (Alerts, Status updates)
    async sendMessage(text: string, options: TelegramBot.SendMessageOptions = { parse_mode: 'Markdown' }) {
        if (!this.chatId) return;
        await this._executeSend(this.chatId, text, options);
    }

    // Public method for replying to specific chats (Cmd responses)
    async sendToChat(chatId: number | string, text: string, options: TelegramBot.SendMessageOptions = { parse_mode: 'Markdown' }) {
        await this._executeSend(chatId, text, options);
    }

    async sendAlert(risk: string, summary: string, ip?: string, strikes?: number) {
        if (!this.bot || !this.chatId) return;

        // --- DEDUPLICATION (90% Similarity, 5 Min Window) ---
        const now = Date.now();
        const checkString = `${risk}:${summary}:${ip || ''}`;

        // Exact Match & Similarity Check
        for (const [key, timestamp] of this.sentAlerts.entries()) {
            if (now - timestamp < 5 * 60 * 1000) { // 5 minutes
                if (this.getSimilarity(checkString, key) > 0.9) {
                    log(`[Telegram] 🔇 Suppressed duplicate alert (${Math.round(this.getSimilarity(checkString, key) * 100)}% match).`);
                    return;
                }
            }
        }

        this.sentAlerts.set(checkString, now);
        this.saveState();
        // ----------------------------------------------------

        const icon = risk === "HIGH" ? "🚨" : (risk === "MEDIUM" ? "⚠️" : "ℹ️");
        let message = `${icon} *SENTINEL AI ALERT*\n\n*Risk:* ${risk}\n*Summary:* ${summary}`;

        if (ip) {
            message += `\n*Attacker IP:* \`${ip}\``;
            if (strikes) message += `\n*Strikes:* ${strikes}/5`;
        }

        const options: TelegramBot.SendMessageOptions = { parse_mode: 'Markdown' };

        if (ip && (risk === "HIGH" || risk === "MEDIUM")) {
            const isBanned = this.blocker?.isBlocked(ip);
            if (isBanned) {
                options.reply_markup = {
                    inline_keyboard: [[{ text: `🔓 Unban ${ip}`, callback_data: `unban_${ip}` }]]
                };
            } else {
                options.reply_markup = {
                    inline_keyboard: [[{ text: `🚫 Ban IP ${ip}`, callback_data: `ban_${ip}` }]]
                };
            }
        }

        await this.sendMessage(message, options);
        log(`[Telegram] Alert sent.`);
    }

    async notifyBan(ip: string, reason: string, method?: string) {
        if (!this.bot || !this.chatId) return;

        // Deduplicate ban notifications too
        const now = Date.now();
        const checkString = `BAN:${ip}`;
        const lastSent = this.sentAlerts.get(checkString) || 0;
        if (now - lastSent < 10 * 60 * 1000) { // 10 min cooldown for ban messages
            return;
        }
        this.sentAlerts.set(checkString, now);
        this.saveState();

        // Human-readable method label
        const methodLabels: Record<string, string> = {
            'cloudflare_api': '☁️ Cloudflare API',
            'nginx_deny': '🌐 Nginx Deny',
            'apache_deny': '🌐 Apache Deny',
            'iptables': '🔥 iptables',
        };
        const methodLabel = method ? (methodLabels[method] || method) : '🔥 iptables';

        const opts: TelegramBot.SendMessageOptions = {
            parse_mode: 'Markdown',
            reply_markup: {
                inline_keyboard: [[{ text: `🔓 Unban ${ip}`, callback_data: `unban_${ip}` }]]
            }
        };
        await this.sendMessage(`🚫 **AUTO-BAN TRIGGERED:** IP ${ip}\nMethod: ${methodLabel}\nReason: ${reason}`, opts);
    }
}
