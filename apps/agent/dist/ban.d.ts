export declare class BanManager {
    private strikes;
    private bannedIPs;
    readonly MAX_STRIKES = 5;
    private readonly DB_PATH;
    private readonly BAN_DURATION_MS;
    constructor();
    private loadBannedIPs;
    private saveBannedIPs;
    addStrike(ip: string): number;
    isBanned(ip: string): boolean;
    banIP(ip: string, reason?: string): Promise<boolean>;
    unbanIP(ip: string): Promise<boolean>;
    private cleanupExpiredBans;
    getBannedIPs(): string[];
}
