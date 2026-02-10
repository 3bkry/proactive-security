import os from 'os';
export interface ServerProfile {
    hostname: string;
    platform: string;
    release: string;
    type: string;
    arch: string;
    cpus: number;
    memory: {
        total: number;
        free: number;
        used: number;
        usagePercent: number;
    };
    networkInterfaces: NodeJS.Dict<os.NetworkInterfaceInfo[]>;
    uptime: number;
    cpu: {
        load: number;
    };
    disk: {
        usagePercent: number;
    };
}
export declare function getSystemStats(): ServerProfile;
export declare function getProcessStats(sortBy: 'cpu' | 'memory'): Promise<string[]>;
export declare function getDiskHogs(dir?: string): Promise<string[]>;
