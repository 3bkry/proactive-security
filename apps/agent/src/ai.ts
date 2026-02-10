
import { GoogleGenAI } from "@google/genai";
import OpenAI from "openai";
import { log, CONFIG_FILE } from "@sentinel/core";
import fs from "fs";

export class AIManager {
    private geminiClient: GoogleGenAI | null = null;
    private openaiClient: OpenAI | null = null;

    public provider: "gemini" | "openai" | "zhipu" = "gemini";
    public model: string = "gemini-3-flash-preview"; // Reverted to experimental model

    public initialized: boolean = false;
    public totalTokens: number = 0;
    public totalCost: number = 0;
    public requestCount: number = 0;

    // Rate limiting
    private rateLimitCooldown: number = 0;

    // Deduplication cache
    private analysisCache: Map<string, any> = new Map();

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
}
`;

    public history: Array<{ timestamp: string, log: string, prompt: string, response: any, tokens: number, cost: number }> = [];

    constructor() {
        log("[AI] Neural Engine v1.7 Initialized (Experimental Model: gemini-3-flash-preview)");
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
                if (config.ZHIPU_API_KEY) {
                    // Zhipu uses OpenAI-compatible SDK with custom base URL
                    this.openaiClient = new OpenAI({
                        apiKey: config.ZHIPU_API_KEY,
                        baseURL: "https://open.bigmodel.cn/api/paas/v4/"
                    });
                }

                if (this.provider === "openai") {
                    this.model = config.OPENAI_MODEL || "gpt-4o";
                } else if (this.provider === "zhipu") {
                    this.model = config.ZHIPU_MODEL || "glm-4-plus";
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
    public updateConfig(config: { provider?: string, geminiKey?: string, openaiKey?: string, zhipuKey?: string, model?: string }) {
        if (config.provider) this.provider = config.provider as any;
        if (config.geminiKey) {
            this.geminiClient = new GoogleGenAI({ apiKey: config.geminiKey });
        }
        if (config.openaiKey) {
            this.openaiClient = new OpenAI({ apiKey: config.openaiKey });
        }
        if (config.zhipuKey) {
            this.openaiClient = new OpenAI({
                apiKey: config.zhipuKey,
                baseURL: "https://open.bigmodel.cn/api/paas/v4/"
            });
        }
        if (config.model) this.model = config.model;
        this.initialized = !!(this.geminiClient || this.openaiClient);
    }

    async testConnection(): Promise<boolean> {
        if (!this.initialized) return false;
        try {
            if ((this.provider === "openai" || this.provider === "zhipu") && this.openaiClient) {
                const response = await this.openaiClient.chat.completions.create({
                    model: this.model,
                    messages: [{ role: "user", content: "ping" }],
                    max_tokens: 5
                });
                return !!response.choices[0].message.content;
            } else if (this.geminiClient) {
                const response = await this.geminiClient.models.generateContent({
                    model: this.model,
                    contents: 'ping',
                });
                return !!response.text;
            }
            return false;
        } catch (error) {
            log(`[AI] Connection probe failed: ${error}`);
            return false;
        }
    }

    private getLogFingerprint(logLine: string): string {
        // Strip timestamps (usually at beginning)
        // Strip timestamps (usually at beginning)
        let fingerprint = logLine.replace(/^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}/, ''); // syslog date
        fingerprint = fingerprint.replace(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*/, ''); // ISO date

        // Strip common variable parts like PIDs, UUIDs, IPs to improve hit rate
        fingerprint = fingerprint.replace(/\[\d+\]/, '[PID]'); // [1234] -> [PID]
        fingerprint = fingerprint.replace(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi, '[UUID]');

        // Strip IPs (IPv4)
        fingerprint = fingerprint.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP]');

        // Strip Hex Strings (often hashes or memory addresses)
        fingerprint = fingerprint.replace(/0x[a-fA-F0-9]+/g, '[HEX]');

        // Normalise generic "user 'name'" patterns
        fingerprint = fingerprint.replace(/user\s+['"]\w+['"]/gi, "user '[USER]'");

        return fingerprint.trim();
    }

    async analyze(logLine: string): Promise<{ risk: string, summary: string, ip?: string, action?: string, tokens: number, usage: { totalTokens: number, totalCost: number, requestCount: number } } | null> {
        if (!this.initialized) return null;

        // Check Rate Limit Cooldown
        if (this.rateLimitCooldown > Date.now()) {
            // Silently skip analysis during cooldown to prevent spamming logs
            return null;
        }

        const maxLen = 500;
        const truncatedLine = logLine.length > maxLen ? logLine.substring(0, maxLen) + "...[truncated]" : logLine;

        // 1. Basic suspicious pattern check (Expanded for predictive detection: POST, OPTIONS, Suspicious Chars)
        const suspiciousPatterns = /failed|error|denied|refused|unauthorized|sudo|panic|fatal|exception|union select|eval\(|alert\(|script>|wp-admin|wp-login|\.php|403 |404 |500 |401 |POST |PUT |DELETE |OPTIONS |PATCH |['<>;%()\[\]]|\.\.|\.env|\.git|\.sh|\.exe/i;
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

        // 2. Deduplication check
        const fingerprint = this.getLogFingerprint(truncatedLine);
        if (this.analysisCache.has(fingerprint)) {
            log(`[AI] Cache Hit: Skipping analysis for similar log: ${fingerprint.substring(0, 50)}...`);
            const cachedResult = this.analysisCache.get(fingerprint);

            // If cache hit, we must extract the IP from the CURRENT log if the cached result had an IP
            let currentIp = cachedResult.ip;
            if (cachedResult.ip) {
                // Simple regex extraction for IPv4
                const ipMatch = logLine.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
                if (ipMatch) {
                    currentIp = ipMatch[0];
                }
            }

            return {
                ...cachedResult,
                ip: currentIp,
                tokens: 0, // No new tokens spent
                usage: { totalTokens: this.totalTokens, totalCost: this.totalCost, requestCount: this.requestCount }
            };
        }

        try {
            const prompt = this.promptTemplate.replace("{{log}}", truncatedLine);
            let result: any;
            let tokens = 0;
            let cost = 0;

            if ((this.provider === "openai" || this.provider === "zhipu") && this.openaiClient) {
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
            } else if (this.provider === "gemini" && this.geminiClient) {
                const response = await this.geminiClient.models.generateContent({
                    model: this.model,
                    contents: prompt
                });
                const text = response.text || "";

                const jsonStr = text.replace(/```json/g, '').replace(/```/g, '').trim();
                result = JSON.parse(jsonStr);

                // Gemini usage metadata
                if (response.usageMetadata) {
                    tokens = (response.usageMetadata.promptTokenCount || 0) + (response.usageMetadata.candidatesTokenCount || 0);
                    cost = ((response.usageMetadata.promptTokenCount || 0) / 1000000 * 0.35) + ((response.usageMetadata.candidatesTokenCount || 0) / 1000000 * 0.70);
                } else {
                    // Fallback estimation
                    const inputTokens = Math.ceil(prompt.length / 4);
                    const outputTokens = Math.ceil(text.length / 4);
                    tokens = inputTokens + outputTokens;
                    cost = (inputTokens / 1000000 * 0.35) + (outputTokens / 1000000 * 0.70);
                }
            } else {
                return null; // Provider mismatch or missing client
            }

            if (result) {
                this.totalTokens += tokens;
                this.totalCost += cost;
                this.requestCount++;

                // Cache the result for this fingerprint
                this.analysisCache.set(fingerprint, result);
                if (this.analysisCache.size > 200) {
                    // Primitive LRU: Clear if too big
                    const firstKey = this.analysisCache.keys().next().value;
                    if (firstKey) this.analysisCache.delete(firstKey);
                }

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
            // Unified Cooldown for ANY AI Error (404, 429, 401, etc.)
            const cooldownMs = 5 * 60 * 1000; // 5 minutes
            this.rateLimitCooldown = Date.now() + cooldownMs;

            if (e.message?.includes("429") || e.status === 429) {
                log(`[AI] ⚠️ Quota Exceeded (429). Pausing AI analysis for 5 minutes.`);
            } else if (e.message?.includes("404") || e.status === 404) {
                log(`[AI] ⚠️ Model not found or Access Denied (${this.model}). Falling back to Shield Mode for 5 minutes.`);
            } else {
                log(`[AI] ⚠️ API Error: ${e.message}. Pausing AI for 5 minutes.`);
            }
            return null;
        }

        return null;
    }

    async summarizeIncidents(incidents: any[]): Promise<string> {
        if (!this.initialized || !this.geminiClient) return "AI not initialized.";
        if (this.rateLimitCooldown > Date.now()) return "AI analysis paused due to rate limit cooldown.";
        const prompt = `Analyze these infrastructure and AI security incidents and provide a concise executive summary for an SRE dashboard: ${JSON.stringify(incidents)}`;

        try {
            if ((this.provider === "openai" || this.provider === "zhipu") && this.openaiClient) {
                const response = await this.openaiClient.chat.completions.create({
                    model: this.model,
                    messages: [{ role: "user", content: prompt }]
                });
                return response.choices[0].message.content || "No summary generated.";
            } else if (this.provider === "gemini" && this.geminiClient) {
                const response = await this.geminiClient.models.generateContent({
                    model: this.model,
                    contents: prompt,
                    config: {
                        systemInstruction: "You are a senior SRE and AI Security expert. Provide high-level technical summaries of incidents.",
                        temperature: 0.3,
                    }
                });
                return response.text || "Unable to generate summary.";
            } else {
                return "AI Provider mismatch or missing key.";
            }
        } catch (error: any) {
            if (error.message?.includes("429") || error.status === 429) {
                this.rateLimitCooldown = Date.now() + 5 * 60 * 1000;
                log(`[AI] ⚠️ Quota Exceeded (429) during summary. Pausing AI for 5 minutes.`);
                return "AI paused due to rate limits.";
            }
            log(`[AI] Summary Error: ${error.message}`);
            return `Connection Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
        }
    }

    async getRiskInsight(logEntry: any): Promise<string> {
        if (!this.initialized || !this.geminiClient) return "AI not initialized.";
        if (this.rateLimitCooldown > Date.now()) return "AI paused (Rate Limit).";
        const prompt = `Assess the risk of this AI interaction log. Risk Score is ${logEntry.riskScore}. Model is ${logEntry.model}. Provide a one-sentence recommendation.`;

        try {
            if ((this.provider === "openai" || this.provider === "zhipu") && this.openaiClient) {
                const response = await this.openaiClient.chat.completions.create({
                    model: this.model,
                    messages: [{ role: "user", content: prompt }]
                });
                return response.choices[0].message.content || "No insight generated.";
            } else if (this.provider === "gemini" && this.geminiClient) {
                const response = await this.geminiClient.models.generateContent({
                    model: this.model,
                    contents: prompt,
                    config: {
                        systemInstruction: "You are a senior SRE and AI Security expert. Provide high-level technical summaries of incidents.",
                        temperature: 0.3,
                    }
                });
                return response.text || "Risk analysis unavailable.";
            } else {
                return "AI Provider mismatch or missing key.";
            }
        } catch (error: any) {
            if (error.message?.includes("429") || error.status === 429) {
                this.rateLimitCooldown = Date.now() + 5 * 60 * 1000;
                return "AI paused (Rate Limit).";
            }
            log(`[AI] Risk insight error: ${error.message}`);
            return "Risk analysis failure (404/Connection). Check API Key and Model availability.";
        }
    }

    async enrichAnalysis(logLine: string, initialResult: any): Promise<any> {
        if (!this.initialized) return initialResult;
        if (this.rateLimitCooldown > Date.now()) return initialResult;

        const maxLen = 1000;
        const truncatedLine = logLine.length > maxLen ? logLine.substring(0, maxLen) + "...[truncated]" : logLine;

        const prompt = `You are a Lead Forensic Security Architect.
A local rule engine has already flagged the following log as suspicious.
I need you to perform a DEEP FORENSIC ENRICHMENT.

Log: "{{log}}"
Heuristic Finding: {{summary}}
Initial Risk: {{risk}}

Your task:
1. Identify the specific vulnerability or component being targeted.
2. Formulate a technical explanation of the exploit's intent.
3. Predict the attacker's likely next step if this succeeds.
4. Recommend advanced mitigation beyond just blocking the IP.

Respond ONLY with this JSON structure:
{
  "risk": "HIGH",
  "summary": "Detailed technical forensic summary",
  "forensics": {
    "target": "The specific component or exploit (e.g., 'CVE-2023-xxxx' or 'PHP-Wrapper bypass')",
    "intent": "Attacker's likely goal",
    "prediction": "What the attacker will do next",
    "mitigation": "Advanced defensive steps"
  }
}
`
            .replace("{{log}}", truncatedLine)
            .replace("{{summary}}", initialResult.summary)
            .replace("{{risk}}", initialResult.risk);

        try {
            let enrichedResult: any;
            if (this.provider === "gemini" && this.geminiClient) {
                const response = await this.geminiClient.models.generateContent({
                    model: this.model,
                    contents: prompt,
                    config: { temperature: 0.1 }
                });
                const text = response.text || "{}";
                enrichedResult = JSON.parse(text.replace(/```json/g, '').replace(/```/g, '').trim());
            } else if ((this.provider === "openai" || this.provider === "zhipu") && this.openaiClient) {
                const response = await this.openaiClient.chat.completions.create({
                    model: this.model,
                    messages: [{ role: "user", content: prompt }],
                    response_format: { type: "json_object" }
                });
                enrichedResult = JSON.parse(response.choices[0].message.content || "{}");
            }

            if (enrichedResult && enrichedResult.forensics) {
                return {
                    ...initialResult,
                    summary: enrichedResult.summary,
                    forensics: enrichedResult.forensics,
                    isEnriched: true
                };
            }
        } catch (e: any) {
            // Also trigger cooldown on enrichment failure
            this.rateLimitCooldown = Date.now() + 5 * 60 * 1000;
            log(`[AI] Forensic enrichment failed: ${e.message}. Pausing AI for 5 minutes.`);
        }

        return initialResult;
    }
}
