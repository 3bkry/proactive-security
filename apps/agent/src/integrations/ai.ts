
import { GoogleGenerativeAI } from "@google/generative-ai";
import OpenAI from "openai";
import { log } from "@sentinel/core";

export interface AIConfig {
    provider: "gemini" | "openai" | "zhipu" | "none";
    geminiKey?: string;
    openaiKey?: string;
    zhipuKey?: string;
    model?: string;
}

export interface AIAnalysisResult {
    risk: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    summary: string;
    action: string;
    confidence: number;
    tokens: number;
    usage?: { totalTokens: number, totalCost: number, requestCount: number };
    mitre?: string;
}

export class AIManager {
    private genAI: GoogleGenerativeAI | null = null;
    private openai: OpenAI | null = null;
    public config: AIConfig = { provider: "none" };
    public totalTokens = 0;
    public totalCost = 0;
    public requestCount = 0;
    public initialized = false;

    // Default Prompt Template
    public promptTemplate = `You are a cybersecurity expert analyzing a security alert from Wazuh.
    
    Log Entry: {log}
    Rule: {rule_description} (Level: {rule_level})
    Groups: {rule_groups}
    
    Analyze this event. Determine the true RISK LEVEL and recommend an ACTION.
    
    Structure your response as JSON:
    {
      "risk": "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
      "summary": "Brief explanation (max 20 words)",
      "action": "Recommended action (e.g., Block IP, Ignore, Investigate)",
      "confidence": 0-100,
      "mitre": "MITRE Tactic/Technique if applicable (or N/A)"
    }`;

    constructor() {
        // Load keys from ENV or wait for config update
        this.updateConfig({
            provider: (process.env.AI_PROVIDER as any) || "none",
            geminiKey: process.env.GEMINI_API_KEY,
            openaiKey: process.env.OPENAI_API_KEY
        });
    }

    public updateConfig(newConfig: AIConfig) {
        this.config = { ...this.config, ...newConfig };

        if (this.config.provider === "gemini" && this.config.geminiKey) {
            this.genAI = new GoogleGenerativeAI(this.config.geminiKey);
            this.initialized = true;
            log(`[AI] Initialized with Gemini`);
        } else if (this.config.provider === "openai" && this.config.openaiKey) {
            this.openai = new OpenAI({ apiKey: this.config.openaiKey });
            this.initialized = true;
            log(`[AI] Initialized with OpenAI`);
        } else {
            this.initialized = false;
        }
    }

    public async analyzeWazuhAlert(alert: any): Promise<AIAnalysisResult | null> {
        if (!this.initialized) return null;

        const logEntry = JSON.stringify(alert.full_log || alert.data || alert);
        const ruleDesc = alert.rule?.description || "Unknown Rule";
        const ruleLevel = alert.rule?.level || 0;
        const ruleGroups = alert.rule?.groups?.join(", ") || "None";

        const prompt = this.promptTemplate
            .replace("{log}", logEntry)
            .replace("{rule_description}", ruleDesc)
            .replace("{rule_level}", ruleLevel.toString())
            .replace("{rule_groups}", ruleGroups);

        try {
            this.requestCount++;
            let responseText = "";
            let tokens = 0;

            if (this.config.provider === "gemini" && this.genAI) {
                const model = this.genAI.getGenerativeModel({ model: this.config.model || "gemini-1.5-flash" });
                const result = await model.generateContent(prompt);
                const response = result.response;
                responseText = response.text();
                // Estimate tokens for Gemini (approx)
                tokens = responseText.length / 4;
                this.totalCost += (tokens / 1000) * 0.0005; // Approx flash cost
            } else if (this.config.provider === "openai" && this.openai) {
                const completion = await this.openai.chat.completions.create({
                    messages: [{ role: "system", content: "You are a security analyst." }, { role: "user", content: prompt }],
                    model: this.config.model || "gpt-3.5-turbo",
                });
                responseText = completion.choices[0].message.content || "";
                tokens = completion.usage?.total_tokens || 0;
                this.totalCost += (tokens / 1000) * 0.0015; // Approx gpt-3.5 cost
            }

            this.totalTokens += tokens;

            // Simple JSON cleanup if model wraps in markdown
            const jsonStr = responseText.replace(/```json/g, "").replace(/```/g, "").trim();
            const result = JSON.parse(jsonStr);

            return {
                risk: result.risk,
                summary: result.summary,
                action: result.action,
                confidence: result.confidence,
                mitre: result.mitre,
                tokens: tokens,
                usage: { totalTokens: this.totalTokens, totalCost: this.totalCost, requestCount: this.requestCount }
            };

        } catch (e) {
            log(`[AI] Analysis failed: ${e}`);
            return null;
        }
    }
}
