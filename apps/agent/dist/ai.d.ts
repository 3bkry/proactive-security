export declare class AIManager {
    private geminiClient;
    private openaiClient;
    provider: "gemini" | "openai";
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
    private initializeFromConfig;
    /**
     * Update AI configuration dynamically (usually from Cloud Pulse)
     */
    updateConfig(config: {
        provider?: string;
        geminiKey?: string;
        openaiKey?: string;
        model?: string;
    }): void;
    analyze(logLine: string): Promise<{
        risk: string;
        summary: string;
        ip?: string;
        action?: string;
        tokens: number;
        usage: {
            totalTokens: number;
            totalCost: number;
            requestCount: number;
        };
    } | null>;
    summarizeIncidents(incidents: any[]): Promise<string>;
    getRiskInsight(logEntry: any): Promise<string>;
}
