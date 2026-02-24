import { Threat, LogEvent } from "./types";
export declare class SentinelDB {
    private db;
    constructor(path: string);
    private initialize;
    saveThreat(threat: Threat): void;
    saveEvent(event: LogEvent): void;
    indexLog(line: string, source: string): void;
    searchLogs(query: string, limit?: number): any[];
    getThreats(limit?: number): Threat[];
    saveBlock(record: any): void;
    removeBlock(ip: string): void;
    getActiveBlocks(): Record<string, any>;
}
