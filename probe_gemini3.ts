
import { GoogleGenAI } from "@google/genai";
import fs from "fs";
import os from "os";
import path from "path";

async function probe() {
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

    const m = "gemini-3-flash-preview";
    try {
        console.log(`Testing ${m}...`);
        const result = await client.models.generateContent({
            model: m,
            contents: "hi",
        });
        console.log("✅ Success:", result.text);
    } catch (e: any) {
        console.log(`❌ Fail: ${e.message}`);
    }
}
probe();
