
import { GoogleGenAI } from "@google/genai";
import { log } from "@sentinel/core";
import fs from "fs";
import os from "os";
import path from "path";

export class AIManager {
    private client: GoogleGenAI | null = null;
    public model: string = "gemini-3-flash-preview";
    public initialized: boolean = false;
    public totalTokens: number = 0;
    public totalCost: number = 0;
    public requestCount: number = 0;

    public promptTemplate: string = `You are an elite Cyber Security Analyst. 
Analyze the following log entry and determine if it represents a threat (Intrusion, SQL Injection, DOS, SSH Bruteforce, etc.).

Log entry: "{{log}}"

Guidelines:
- Risk levels: LOW (Normal activity), MEDIUM (Suspicious but not critical), HIGH (Clear threat/attack).
- IP Extraction: If the log contains an IP address of a potential attacker, identify it.
- Action: Recommend a specific defensive action.

Respond ONLY with this JSON structure:
{
  "risk": "LOW" | "MEDIUM" | "HIGH",
  "summary": "Professional dry summary of the finding",
  "ip": "extracted_ip_or_null",
  "action": "Brief recommendation"
}`;

    public history: Array<{ timestamp: string, log: string, prompt: string, response: any, tokens: number, cost: number }> = [];

    constructor() {
        this.initialize();
    }

    private getApiKey(): string | null {
        // Preference: Config file > Env var
        const configPath = path.join(os.homedir(), ".sentinel", "config.json");
        if (fs.existsSync(configPath)) {
            try {
                const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
                if (config.GEMINI_API_KEY) return config.GEMINI_API_KEY;
            } catch (e) { }
        }
        return process.env.GEMINI_API_KEY || null;
    }

    private getClient() {
        const apiKey = this.getApiKey();
        if (!apiKey) return null;
        return new GoogleGenAI({ apiKey });
    }

    private initialize() {
        const apiKey = this.getApiKey();
        if (apiKey) {
            this.client = new GoogleGenAI({ apiKey });
            this.initialized = true;
            log(`[AI] Google GenAI SDK initialized with model: ${this.model}`);
        } else {
            log("[AI] No API Key found. Run 'sentinelctl config GEMINI_API_KEY <key>' to enable AI.");
        }
    }

    async analyze(logLine: string): Promise<{ risk: string, summary: string, ip?: string, action?: string, usage?: { totalTokens: number, totalCost: number, requestCount: number } } | null> {
        const client = this.getClient();
        if (!client) return null;

        const maxLen = 500;
        const truncatedLine = logLine.length > maxLen ? logLine.substring(0, maxLen) + "...[truncated]" : logLine;

        const suspiciousPatterns = /failed|error|denied|refused|unauthorized|sudo|panic|fatal|exception/i;
        if (!suspiciousPatterns.test(logLine)) {
            return {
                risk: "SAFE",
                summary: "No suspicious keywords found",
                ip: undefined,
                action: "Skipped",
                usage: { totalTokens: this.totalTokens, totalCost: this.totalCost, requestCount: this.requestCount }
            };
        }

        const modelsToTry = [this.model, "gemini-2.0-flash", "gemini-1.5-flash"];
        let lastError = "";

        for (const modelName of modelsToTry) {
            try {
                const prompt = this.promptTemplate.replace("{{log}}", truncatedLine);
                const inputTokens = Math.ceil(prompt.length / 4);

                const response = await client.models.generateContent({
                    model: modelName,
                    contents: prompt,
                });

                const text = response.text;
                if (!text) throw new Error("Empty response from AI");

                const outputTokens = Math.ceil(text.length / 4);
                // Gemini 3 Preview Pricing (Estimation fallback to 1.5 Flash rates for tracking)
                const inputCost = (inputTokens / 1000000) * 0.35;
                const outputCost = (outputTokens / 1000000) * 0.70;

                this.totalTokens += (inputTokens + outputTokens);
                this.totalCost += (inputCost + outputCost);
                this.requestCount++;

                const jsonStr = text.replace(/```json/g, '').replace(/```/g, '').trim();
                const result = JSON.parse(jsonStr);

                this.history.unshift({
                    timestamp: new Date().toISOString(),
                    log: truncatedLine,
                    prompt: prompt,
                    response: result,
                    tokens: inputTokens + outputTokens,
                    cost: inputCost + outputCost
                });
                if (this.history.length > 50) this.history.pop();

                return {
                    ...result,
                    usage: { totalTokens: this.totalTokens, totalCost: this.totalCost, requestCount: this.requestCount }
                };
            } catch (e: any) {
                lastError = e.message;
                if (!lastError.includes("404") && !lastError.includes("429")) break;
            }
        }

        return null;
    }

    // New methods requested by USER
    async summarizeIncidents(incidents: any[]): Promise<string> {
        const client = this.getClient();
        if (!client) return "API Key missing.";

        try {
            const response = await client.models.generateContent({
                model: this.model,
                contents: `Analyze these infrastructure and AI security incidents and provide a concise executive summary for an SRE dashboard: ${JSON.stringify(incidents)}`,
                config: {
                    systemInstruction: "You are a senior SRE and AI Security expert. Provide high-level technical summaries of incidents.",
                    temperature: 0.3,
                }
            });
            return response.text || "Unable to generate summary.";
        } catch (error: any) {
            return `Summary Error: ${error.message}`;
        }
    }

    async getRiskInsight(logEntry: any): Promise<string> {
        const client = this.getClient();
        if (!client) return "API Key missing.";

        try {
            const response = await client.models.generateContent({
                model: this.model,
                contents: `Assess the risk of this AI interaction log. Risk Score is ${logEntry.riskScore}. Model is ${logEntry.model}. Provide a one-sentence recommendation.`,
            });
            return response.text || "Risk analysis unavailable.";
        } catch (error: any) {
            return `Risk Insight Error: ${error.message}`;
        }
    }
}
