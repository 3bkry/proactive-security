export declare class AIManager {
    private client;
    model: string;
    initialized: boolean;
    totalTokens: number;
    totalCost: number;
    requestCount: number;
    promptTemplate: string;
    history: Array<{
        timestamp: string;
        log: string;
        prompt: string;
        response: any;
        tokens: number;
        cost: number;
    }>;
    constructor();
    private getApiKey;
    private getClient;
    private initialize;
    analyze(logLine: string): Promise<{
        risk: string;
        summary: string;
        ip?: string;
        action?: string;
        usage?: {
            totalTokens: number;
            totalCost: number;
            requestCount: number;
        };
    } | null>;
    summarizeIncidents(incidents: any[]): Promise<string>;
    getRiskInsight(logEntry: any): Promise<string>;
}
