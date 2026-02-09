
import { GoogleGenAI } from "@google/genai";
import fs from "fs";
import os from "os";
import path from "path";

async function listModels() {
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

    const genAI = new GoogleGenAI({ apiKey });

    const models = ["gemini-1.5-flash", "gemini-1.5-flash-latest", "gemini-1.0-pro"];

    for (const m of models) {
        try {
            console.log(`Testing model: ${m}...`);
            const result = await genAI.models.generateContent({
                model: m,
                contents: "Hello, this is a test.",
            });
            console.log(`✅ Success with ${m}:`, result.text);
            break;
        } catch (e) {
            console.error(`❌ Failed with ${m}:`, e);
        }
    }
}

listModels();
