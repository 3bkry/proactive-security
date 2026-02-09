export * from "./types";
export * from "./db";
export * from "./system";

export const CORE_VERSION = "0.1.0";

export function log(message: string) {
    console.log(`[CORE] ${message}`);
}
