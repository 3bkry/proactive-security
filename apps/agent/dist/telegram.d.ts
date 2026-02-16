import TelegramBot from 'node-telegram-bot-api';
import { Blocker } from './defense/blocker.js';
export declare class TelegramNotifier {
    private bot;
    private chatId;
    private blocker;
    private sentAlerts;
    private isRateLimited;
    private rateLimitResetTime;
    constructor(blocker?: Blocker | any);
    private loadState;
    private saveState;
    private initialize;
    onCommand(command: string, handler: (msg: TelegramBot.Message) => void): void;
    private getSimilarity;
    private _executeSend;
    sendMessage(text: string, options?: TelegramBot.SendMessageOptions): Promise<void>;
    sendToChat(chatId: number | string, text: string, options?: TelegramBot.SendMessageOptions): Promise<void>;
    sendAlert(risk: string, summary: string, ip?: string, strikes?: number): Promise<void>;
    notifyBan(ip: string, reason: string): Promise<void>;
}
