import TelegramBot from 'node-telegram-bot-api';
import { log } from '@sentinel/core';
import fs from 'fs';
import os from 'os';
import path from 'path';
export class TelegramNotifier {
    bot = null;
    chatId = null;
    banManager = null;
    constructor(banManager) {
        if (banManager)
            this.banManager = banManager;
        this.initialize();
    }
    initialize() {
        try {
            const configPath = path.join(os.homedir(), ".sentinel", "config.json");
            if (fs.existsSync(configPath)) {
                const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
                const token = config.TELEGRAM_BOT_TOKEN;
                this.chatId = config.TELEGRAM_CHAT_ID;
                if (token && this.chatId) {
                    // Enable polling to receive button clicks and commands
                    this.bot = new TelegramBot(token, { polling: true });
                    log("[Telegram] Initialized successfully with polling.");
                    this.bot.on('callback_query', async (query) => {
                        const action = query.data;
                        if (!action || !this.banManager)
                            return;
                        if (action.startsWith('ban_')) {
                            const ip = action.split('_')[1];
                            await this.banManager.banIP(ip, "Manual Ban via Telegram");
                            // Acknowledge logic
                            if (query.id) {
                                this.bot?.answerCallbackQuery(query.id, { text: `IP ${ip} Banned!` });
                                const opts = {
                                    parse_mode: 'Markdown',
                                    reply_markup: {
                                        inline_keyboard: [[{ text: `🔓 Unban ${ip}`, callback_data: `unban_${ip}` }]]
                                    }
                                };
                                this.bot?.sendMessage(query.message.chat.id, `🚫 **IP BANNED MANUALLY:** ${ip}`, opts);
                            }
                        }
                        else if (action.startsWith('unban_')) {
                            const ip = action.split('_')[1];
                            await this.banManager.unbanIP(ip);
                            if (query.id) {
                                this.bot?.answerCallbackQuery(query.id, { text: `IP ${ip} Unbanned!` });
                                this.bot?.sendMessage(query.message.chat.id, `✅ **IP UNBANNED:** ${ip}`, { parse_mode: 'Markdown' });
                            }
                        }
                    });
                    // Handle standard commands
                    this.bot.onText(/\/help/, (msg) => {
                        if (String(msg.chat.id) !== String(this.chatId))
                            return;
                        const helpMsg = `🛡️ *SentinelAI Bot Help*\n\n` +
                            `/status - Check server & security status\n` +
                            `/stats - AI analysis & cost stats\n` +
                            `/banned - List currently blocked IPs\n` +
                            `/help - Show this message`;
                        this.bot?.sendMessage(msg.chat.id, helpMsg, { parse_mode: 'Markdown' });
                    });
                }
            }
        }
        catch (e) {
            log(`[Telegram] Initialization failed: ${e}`);
        }
    }
    onCommand(command, handler) {
        this.bot?.onText(new RegExp(`^\\/${command}`), (msg) => {
            if (String(msg.chat.id) !== String(this.chatId))
                return;
            handler(msg);
        });
    }
    async sendMessage(text, options = { parse_mode: 'Markdown' }) {
        if (!this.bot || !this.chatId)
            return;
        try {
            await this.bot.sendMessage(this.chatId, text, options);
        }
        catch (e) {
            log(`[Telegram] Failed to send message: ${e}`);
        }
    }
    async sendAlert(risk, summary, ip, strikes) {
        if (!this.bot || !this.chatId)
            return;
        const icon = risk === "HIGH" ? "🚨" : (risk === "MEDIUM" ? "⚠️" : "ℹ️");
        let message = `${icon} *SENTINEL AI ALERT*\n\n*Risk:* ${risk}\n*Summary:* ${summary}`;
        if (ip) {
            message += `\n*Attacker IP:* \`${ip}\``;
            if (strikes)
                message += `\n*Strikes:* ${strikes}/5`;
        }
        const options = { parse_mode: 'Markdown' };
        // Add Ban Button if IP is present and Risk is High/Medium
        if (ip && (risk === "HIGH" || risk === "MEDIUM")) {
            // Check if already banned to show unban or ban
            const isBanned = this.banManager?.isBanned(ip);
            if (isBanned) {
                options.reply_markup = {
                    inline_keyboard: [[{ text: `🔓 Unban ${ip}`, callback_data: `unban_${ip}` }]]
                };
            }
            else {
                options.reply_markup = {
                    inline_keyboard: [[{ text: `🚫 Ban IP ${ip}`, callback_data: `ban_${ip}` }]]
                };
            }
        }
        try {
            await this.bot.sendMessage(this.chatId, message, options);
            log(`[Telegram] Alert sent.`);
        }
        catch (e) {
            log(`[Telegram] Failed to send alert: ${e}`);
        }
    }
    async notifyBan(ip, reason) {
        if (!this.bot || !this.chatId)
            return;
        try {
            const opts = {
                parse_mode: 'Markdown',
                reply_markup: {
                    inline_keyboard: [[{ text: `🔓 Unban ${ip}`, callback_data: `unban_${ip}` }]]
                }
            };
            await this.bot.sendMessage(this.chatId, `🚫 **AUTO-BAN TRIGGERED:** IP ${ip}\nReason: ${reason}`, opts);
        }
        catch (e) {
            log(`[Telegram] Failed to send ban notification: ${e}`);
        }
    }
}
//# sourceMappingURL=telegram.js.map