
import { GoogleGenAI } from "@google/genai";
import fs from "fs";
import os from "os";
import path from "path";

async function probe() {
    const configPath = path.join(os.homedir(), ".sentinel", "config.json");
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    const client = new GoogleGenAI({ apiKey: config.GEMINI_API_KEY });

    const m = "gemini-pro";
    try {
        console.log(`Testing ${m}...`);
        await client.models.generateContent({ model: m, contents: "hi" });
        console.log("✅ Success");
    } catch (e: any) {
        console.log(`❌ Fail: ${e.message}`);
    }
}
probe();
