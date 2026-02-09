
import { GoogleGenAI } from "@google/genai";
import fs from "fs";
import os from "os";
import path from "path";

async function listAllModels() {
    const configPath = path.join(os.homedir(), ".sentinel", "config.json");
    if (!fs.existsSync(configPath)) {
        console.error("No config file found");
        return;
    }
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    const apiKey = config.GEMINI_API_KEY;

    if (!apiKey) {
        console.error("No API key found");
        return;
    }

    const client = new GoogleGenAI({ apiKey });

    try {
        console.log("Listing models...");
        // In the new @google/genai SDK, listing models is done via client.models.list()
        // However, this preview SDK might not have it exposed the same way.
        // Let's try to probe with a simple request to a very standard model.

        const modelsToTry = [
            "gemini-1.5-flash",
            "gemini-1.5-flash-001",
            "gemini-1.5-flash-002",
            "gemini-1.5-pro",
            "gemini-2.0-flash",
            "gemini-2.0-flash-exp"
        ];

        for (const m of modelsToTry) {
            try {
                process.stdout.write(`Testing ${m}... `);
                await client.models.generateContent({
                    model: m,
                    contents: [{ role: 'user', parts: [{ text: 'hi' }] }],
                    config: { maxOutputTokens: 10 }
                });
                console.log("✅ WORKS");
            } catch (e: any) {
                console.log(`❌ FAIL (${e.status || e.message})`);
            }
        }
    } catch (e) {
        console.error("Global Error:", e);
    }
}

listAllModels();
