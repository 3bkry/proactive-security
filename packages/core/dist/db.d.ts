import { Threat, LogEvent } from "./types";
export declare class SentinelDB {
    private db;
    constructor(path: string);
    private initialize;
    saveThreat(threat: Threat): void;
    saveEvent(event: LogEvent): void;
    getThreats(limit?: number): Threat[];
}
