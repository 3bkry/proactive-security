
import TelegramBot from 'node-telegram-bot-api';
import { log, CONFIG_FILE } from '@sentinel/core';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { BanManager } from './ban.js';

export class TelegramNotifier {
    private bot: TelegramBot | null = null;
    private chatId: string | null = null;
    private banManager: BanManager | null = null;

    private sentAlerts = new Map<string, number>();
    private isRateLimited = false;
    private rateLimitResetTime = 0;

    constructor(banManager?: BanManager) {
        if (banManager) this.banManager = banManager;
        this.initialize();

        // Cleanup old alerts every 10 minutes
        setInterval(() => {
            const now = Date.now();
            for (const [key, timestamp] of this.sentAlerts.entries()) {
                if (now - timestamp > 10 * 60 * 1000) {
                    this.sentAlerts.delete(key);
                }
            }
        }, 10 * 60 * 1000);
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
                        if (!action || !this.banManager) return;

                        if (action.startsWith('ban_')) {
                            const ip = action.split('_')[1];
                            await this.banManager.banIP(ip, "Manual Ban via Telegram");

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
                            await this.banManager.unbanIP(ip);

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
        // ----------------------------------------------------

        const icon = risk === "HIGH" ? "🚨" : (risk === "MEDIUM" ? "⚠️" : "ℹ️");
        let message = `${icon} *SENTINEL AI ALERT*\n\n*Risk:* ${risk}\n*Summary:* ${summary}`;

        if (ip) {
            message += `\n*Attacker IP:* \`${ip}\``;
            if (strikes) message += `\n*Strikes:* ${strikes}/5`;
        }

        const options: TelegramBot.SendMessageOptions = { parse_mode: 'Markdown' };

        if (ip && (risk === "HIGH" || risk === "MEDIUM" || risk === "CRITICAL")) {
            const isBanned = this.banManager?.isBanned(ip);
            const keyboard = [];

            if (isBanned) {
                keyboard.push([{ text: `🔓 Unban ${ip}`, callback_data: `unban_${ip}` }]);
            } else {
                keyboard.push([{ text: `🚫 Block IP ${ip}`, callback_data: `ban_${ip}` }]);
            }

            // AI Analysis Button
            keyboard.push([{ text: `🧠 AI Analyze`, callback_data: `analyze_${ip}` }]);

            options.reply_markup = {
                inline_keyboard: keyboard
            };
        }

        await this.sendMessage(message, options);
        log(`[Telegram] Alert sent.`);
    }

    async notifyBan(ip: string, reason: string) {
        if (!this.bot || !this.chatId) return;
        const opts: TelegramBot.SendMessageOptions = {
            parse_mode: 'Markdown',
            reply_markup: {
                inline_keyboard: [[{ text: `🔓 Unban ${ip}`, callback_data: `unban_${ip}` }]]
            }
        };
        await this.sendMessage(`🚫 **AUTO-BAN TRIGGERED:** IP ${ip}\nReason: ${reason}`, opts);
    }
}
