
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

export function getSystemStats(): ServerProfile {
    const total = os.totalmem();
    const free = os.freemem();

    const loadAvg = os.loadavg();
    const cpuCount = os.cpus().length;
    // Load avg is usually 0-N where N is num cores. Normalize to 0-100%.
    const cpuLoad = Math.min(Math.round((loadAvg[0] / cpuCount) * 100), 100);

    let diskUsage = 0;
    try {
        const { execSync } = require('child_process');
        // Get usage of root partition
        const dfOut = execSync("df -h / | tail -1 | awk '{print $5}'").toString().trim();
        diskUsage = parseInt(dfOut.replace('%', '')) || 0;
    } catch (e) { }

    return {
        hostname: os.hostname(),
        platform: os.platform(),
        release: os.release(),
        type: os.type(),
        arch: os.arch(),
        cpus: cpuCount,
        memory: {
            total,
            free,
            used: total - free,
            usagePercent: Math.round(((total - free) / total) * 100)
        },
        networkInterfaces: os.networkInterfaces(),
        uptime: os.uptime(),
        cpu: {
            load: cpuLoad
        },
        disk: {
            usagePercent: diskUsage
        }
    };
}

export async function getProcessStats(sortBy: 'cpu' | 'memory'): Promise<string[]> {
    const { exec } = require('child_process');
    const sortFlag = sortBy === 'cpu' ? '-%cpu' : '-%mem';
    return new Promise((resolve) => {
        exec(`ps -eo pid,comm,%cpu,%mem --sort=${sortFlag} | head -n 6`, (err: any, stdout: string) => {
            if (err) return resolve([]);
            const lines = stdout.trim().split('\n').slice(1); // skip header
            resolve(lines.map(line => line.trim()));
        });
    });
}

export async function getDiskHogs(dir: string = '/var/log'): Promise<string[]> {
    const { exec } = require('child_process');
    return new Promise((resolve) => {
        // Find top 5 largest files in dir, suppress errors
        exec(`find ${dir} -type f -exec du -h {} + 2>/dev/null | sort -rh | head -n 5`, (err: any, stdout: string) => {
            if (err) return resolve([]);
            resolve(stdout.trim().split('\n'));
        });
    });
}
