
import { GoogleGenAI } from "@google/genai";
import fs from "fs";
import os from "os";
import path from "path";

async function listModels() {
    const configPath = path.join(os.homedir(), ".sentinel", "config.json");
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    const apiKey = config.GEMINI_API_KEY;

    if (!apiKey) {
        console.error("No API key found");
        return;
    }

    const genAI = new GoogleGenAI(apiKey);
    // The SDK doesn't have a direct listModels, we have to try one.
    // Actually, let's try gemini-1.5-flash
    try {
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
        const result = await model.generateContent("test");
        console.log("Success with gemini-1.5-flash:", result.response.text());
    } catch (e) {
        console.error("Failed with gemini-1.5-flash:", e);
    }

    try {
        const model = genAI.getGenerativeModel({ model: "gemini-pro" });
        const result = await model.generateContent("test");
        console.log("Success with gemini-pro:", result.response.text());
    } catch (e) {
        console.error("Failed with gemini-pro:", e);
    }
}

listModels();
