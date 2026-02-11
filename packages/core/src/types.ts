export enum Severity {
    LOW = "low",
    MEDIUM = "medium",
    HIGH = "high",
    CRITICAL = "critical",
}

export interface LogEvent {
    source: string;
    timestamp: Date;
    raw: string;
    metadata?: Record<string, any>;
}

export interface Threat {
    id: string;
    severity: Severity;
    source_ip: string;
    description: string;
    timestamp: Date;
    raw_log: string;
    rule_id?: string;
}

export interface DetectionRule {
    id: string;
    name: string;
    description?: string;
    pattern: RegExp;
    severity: Severity;
}

export interface SentinelConfig {
    TELEGRAM_BOT_TOKEN?: string;
    TELEGRAM_CHAT_ID?: string;
    OPENAI_API_KEY?: string;
    GEMINI_API_KEY?: string;
    ZHIPU_API_KEY?: string;
    AI_PROVIDER?: "openai" | "gemini" | "zhipu";
    AI_MODEL?: string;
    WHITELIST_IPS?: string[];
    // How many existing lines to scan on startup (default: 0 or 500)
    STARTUP_READ_LINES?: number;
}
