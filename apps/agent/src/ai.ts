
import { GoogleGenAI } from "@google/genai";
import OpenAI from "openai";
import { log, CONFIG_FILE } from "@sentinel/core";
import fs from "fs";

export class AIManager {
    private geminiClient: GoogleGenAI | null = null;
    private openaiClient: OpenAI | null = null;

    public provider: "gemini" | "openai" = "gemini";
    public model: string = "gemini-3-flash-preview"; // Default

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
        this.initializeFromConfig();
    }

    private initializeFromConfig() {
        if (fs.existsSync(CONFIG_FILE)) {
            try {
                const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
                if (config.AI_PROVIDER) this.provider = config.AI_PROVIDER;

                if (config.GEMINI_API_KEY) {
                    this.geminiClient = new GoogleGenAI({ apiKey: config.GEMINI_API_KEY });
                }
                if (config.OPENAI_API_KEY) {
                    this.openaiClient = new OpenAI({ apiKey: config.OPENAI_API_KEY });
                }

                if (this.provider === "openai") {
                    this.model = config.OPENAI_MODEL || "gpt-4o";
                } else {
                    this.model = config.GEMINI_MODEL || "gemini-3-flash-preview";
                }

                this.initialized = !!(this.geminiClient || this.openaiClient);
            } catch (e) { }
        }
    }

    /**
     * Update AI configuration dynamically (usually from Cloud Pulse)
     */
    public updateConfig(config: { provider?: string, geminiKey?: string, openaiKey?: string, model?: string }) {
        if (config.provider) this.provider = config.provider as any;
        if (config.geminiKey) {
            this.geminiClient = new GoogleGenAI({ apiKey: config.geminiKey });
        }
        if (config.openaiKey) {
            this.openaiClient = new OpenAI({ apiKey: config.openaiKey });
        }
        if (config.model) this.model = config.model;
        this.initialized = !!(this.geminiClient || this.openaiClient);
    }

    async analyze(logLine: string): Promise<{ risk: string, summary: string, ip?: string, action?: string, tokens: number, usage: { totalTokens: number, totalCost: number, requestCount: number } } | null> {
        if (!this.initialized) return null;

        const maxLen = 500;
        const truncatedLine = logLine.length > maxLen ? logLine.substring(0, maxLen) + "...[truncated]" : logLine;

        const suspiciousPatterns = /failed|error|denied|refused|unauthorized|sudo|panic|fatal|exception/i;
        if (!suspiciousPatterns.test(logLine)) {
            return {
                risk: "SAFE",
                summary: "No suspicious keywords found",
                ip: undefined,
                action: "Skipped",
                tokens: 0,
                usage: { totalTokens: this.totalTokens, totalCost: this.totalCost, requestCount: this.requestCount }
            };
        }

        try {
            const prompt = this.promptTemplate.replace("{{log}}", truncatedLine);
            let result: any;
            let tokens = 0;
            let cost = 0;

            if (this.provider === "openai" && this.openaiClient) {
                const response = await this.openaiClient.chat.completions.create({
                    model: this.model,
                    messages: [{ role: "user", content: prompt }],
                    response_format: { type: "json_object" }
                });

                const text = response.choices[0].message.content || "{}";
                result = JSON.parse(text);
                tokens = response.usage?.total_tokens || 0;

                // Pricing for GPT-4o (est)
                cost = ((response.usage?.prompt_tokens || 0) / 1000000 * 5) + ((response.usage?.completion_tokens || 0) / 1000000 * 15);
            } else if (this.geminiClient) {
                const model = (this.geminiClient as any).getGenerativeModel({ model: this.model });
                const response = await model.generateContent(prompt);
                const text = response.response.text();

                const jsonStr = text.replace(/```json/g, '').replace(/```/g, '').trim();
                result = JSON.parse(jsonStr);

                // Gemini estimation (SDK doesn't always provide tokens easily in same call)
                const inputTokens = Math.ceil(prompt.length / 4);
                const outputTokens = Math.ceil(text.length / 4);
                tokens = inputTokens + outputTokens;
                cost = (inputTokens / 1000000 * 0.35) + (outputTokens / 1000000 * 0.70);
            }

            if (result) {
                this.totalTokens += tokens;
                this.totalCost += cost;
                this.requestCount++;

                this.history.unshift({
                    timestamp: new Date().toISOString(),
                    log: truncatedLine,
                    prompt: prompt,
                    response: result,
                    tokens: tokens,
                    cost: cost
                });
                if (this.history.length > 50) this.history.pop();

                return {
                    ...result,
                    tokens,
                    usage: { totalTokens: this.totalTokens, totalCost: this.totalCost, requestCount: this.requestCount }
                };
            }
        } catch (e: any) {
            log(`[AI] Error during analysis: ${e.message}`);
        }

        return null;
    }

    async summarizeIncidents(incidents: any[]): Promise<string> {
        if (!this.initialized) return "AI not initialized.";
        try {
            const prompt = `Analyze these infrastructure and AI security incidents and provide a concise executive summary for an SRE dashboard: ${JSON.stringify(incidents)}`;
            if (this.provider === "openai" && this.openaiClient) {
                const response = await this.openaiClient.chat.completions.create({
                    model: this.model,
                    messages: [{ role: "user", content: prompt }]
                });
                return response.choices[0].message.content || "No summary generated.";
            } else if (this.geminiClient) {
                const model = (this.geminiClient as any).getGenerativeModel({ model: this.model });
                const response = await model.generateContent(prompt);
                return response.response.text();
            }
        } catch (error: any) {
            return `Summary Error: ${error.message}`;
        }
        return "Provider unavailable.";
    }

    async getRiskInsight(logEntry: any): Promise<string> {
        if (!this.initialized) return "AI not initialized.";
        try {
            const prompt = `Assess the risk of this AI interaction log. Risk Score is ${logEntry.riskScore}. Model is ${logEntry.model}. Provide a one-sentence recommendation.`;
            if (this.provider === "openai" && this.openaiClient) {
                const response = await this.openaiClient.chat.completions.create({
                    model: this.model,
                    messages: [{ role: "user", content: prompt }]
                });
                return response.choices[0].message.content || "No insight generated.";
            } else if (this.geminiClient) {
                const model = (this.geminiClient as any).getGenerativeModel({ model: this.model });
                const response = await model.generateContent(prompt);
                return response.response.text();
            }
        } catch (error: any) {
            return `Risk Insight Error: ${error.message}`;
        }
        return "Provider unavailable.";
    }
}
