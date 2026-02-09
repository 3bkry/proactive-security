
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

export function getSystemStats(): ServerProfile {
    const total = os.totalmem();
    const free = os.freemem();
    return {
        hostname: os.hostname(),
        platform: os.platform(),
        release: os.release(),
        type: os.type(),
        arch: os.arch(),
        cpus: os.cpus().length,
        totalMemory: total,
        freeMemory: free,
        memoryUsage: Math.round(((total - free) / total) * 100),
        networkInterfaces: os.networkInterfaces(),
        uptime: os.uptime()
    };
}
