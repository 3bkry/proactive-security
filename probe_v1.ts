
import { GoogleGenAI } from "@google/genai";
import fs from "fs";
import os from "os";
import path from "path";

async function probe() {
    const configPath = path.join(os.homedir(), ".sentinel", "config.json");
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));

    // Testing v1 API
    const client = new GoogleGenAI({ apiKey: config.GEMINI_API_KEY, apiVersion: 'v1' });

    const m = "gemini-1.5-flash";
    try {
        console.log(`Testing ${m} on v1 API...`);
        await client.models.generateContent({ model: m, contents: "hi" });
        console.log("✅ Success on v1");
    } catch (e: any) {
        console.log(`❌ Fail on v1: ${e.message}`);
    }
}
probe();
