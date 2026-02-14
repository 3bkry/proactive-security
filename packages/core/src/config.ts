
import os from 'os';
import path from 'path';

export const SENTINEL_CONFIG_DIR = process.env.SENTINEL_CONFIG_DIR || path.join(os.homedir(), '.sentinel');
export const SENTINEL_LOG_DIR = process.env.SENTINEL_LOG_DIR || SENTINEL_CONFIG_DIR; // Default to same dir for now
export const SENTINEL_DATA_DIR = process.env.SENTINEL_DATA_DIR || SENTINEL_CONFIG_DIR;


export const CONFIG_FILE = path.join(SENTINEL_CONFIG_DIR, 'config.json');
export const BANNED_IPS_FILE = path.join(SENTINEL_DATA_DIR, 'banned_ips.json');

export interface SentinelConfig {
    WAZUH_ENABLED: boolean;
    WAZUH_WEBHOOK_PORT: number;
    TELEGRAM_BOT_TOKEN?: string;
    TELEGRAM_CHAT_ID?: string;
    AI_PROVIDER?: string;
    GEMINI_API_KEY?: string;
    OPENAI_API_KEY?: string;
    ZHIPU_API_KEY?: string;
}

