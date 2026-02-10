"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getSystemStats = getSystemStats;
exports.getProcessStats = getProcessStats;
exports.getDiskHogs = getDiskHogs;
const os_1 = __importDefault(require("os"));
function getSystemStats() {
    const total = os_1.default.totalmem();
    const free = os_1.default.freemem();
    const loadAvg = os_1.default.loadavg();
    const cpuCount = os_1.default.cpus().length;
    // Load avg is usually 0-N where N is num cores. Normalize to 0-100%.
    const cpuLoad = Math.min(Math.round((loadAvg[0] / cpuCount) * 100), 100);
    let diskUsage = 0;
    try {
        const { execSync } = require('child_process');
        // Get usage of root partition
        const dfOut = execSync("df -h / | tail -1 | awk '{print $5}'").toString().trim();
        diskUsage = parseInt(dfOut.replace('%', '')) || 0;
    }
    catch (e) { }
    return {
        hostname: os_1.default.hostname(),
        platform: os_1.default.platform(),
        release: os_1.default.release(),
        type: os_1.default.type(),
        arch: os_1.default.arch(),
        cpus: cpuCount,
        memory: {
            total,
            free,
            used: total - free,
            usagePercent: Math.round(((total - free) / total) * 100)
        },
        networkInterfaces: os_1.default.networkInterfaces(),
        uptime: os_1.default.uptime(),
        cpu: {
            load: cpuLoad
        },
        disk: {
            usagePercent: diskUsage
        }
    };
}
async function getProcessStats(sortBy) {
    const { exec } = require('child_process');
    const sortFlag = sortBy === 'cpu' ? '-%cpu' : '-%mem';
    return new Promise((resolve) => {
        exec(`ps -eo pid,comm,%cpu,%mem --sort=${sortFlag} | head -n 6`, (err, stdout) => {
            if (err)
                return resolve([]);
            const lines = stdout.trim().split('\n').slice(1); // skip header
            resolve(lines.map(line => line.trim()));
        });
    });
}
async function getDiskHogs(dir = '/var/log') {
    const { exec } = require('child_process');
    return new Promise((resolve) => {
        // Find top 5 largest files in dir, suppress errors
        exec(`find ${dir} -type f -exec du -h {} + 2>/dev/null | sort -rh | head -n 5`, (err, stdout) => {
            if (err)
                return resolve([]);
            resolve(stdout.trim().split('\n'));
        });
    });
}
//# sourceMappingURL=system.js.map