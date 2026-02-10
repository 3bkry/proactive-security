import { EventEmitter } from "events";
export declare class LogWatcher extends EventEmitter {
    private watcher;
    constructor();
    private setupListeners;
    add(path: string): boolean;
    remove(path: string): void;
    getWatchedFiles(): string[];
    static discoverFiles(): string[];
}
