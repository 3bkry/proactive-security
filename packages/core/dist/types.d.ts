export declare enum Severity {
    LOW = "low",
    MEDIUM = "medium",
    HIGH = "high",
    CRITICAL = "critical"
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
