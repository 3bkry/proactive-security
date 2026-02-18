import { EventEmitter } from "events";
export declare class LogWatcher extends EventEmitter {
    private watcher;
    constructor();
    private setupListeners;
    add(filePath: string): boolean;
    remove(filePath: string): void;
    getWatchedFiles(): string[];
    static discoverFiles(): string[];
}
