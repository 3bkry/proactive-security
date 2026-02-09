import os from 'os';
export interface ServerProfile {
    hostname: string;
    platform: string;
    release: string;
    type: string;
    arch: string;
    cpus: number;
    totalMemory: number;
    freeMemory: number;
    memoryUsage: number;
    networkInterfaces: NodeJS.Dict<os.NetworkInterfaceInfo[]>;
    uptime: number;
}
export declare function getSystemStats(): ServerProfile;
