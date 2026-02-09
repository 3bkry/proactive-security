"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getSystemStats = getSystemStats;
const os_1 = __importDefault(require("os"));
function getSystemStats() {
    const total = os_1.default.totalmem();
    const free = os_1.default.freemem();
    return {
        hostname: os_1.default.hostname(),
        platform: os_1.default.platform(),
        release: os_1.default.release(),
        type: os_1.default.type(),
        arch: os_1.default.arch(),
        cpus: os_1.default.cpus().length,
        totalMemory: total,
        freeMemory: free,
        memoryUsage: Math.round(((total - free) / total) * 100),
        networkInterfaces: os_1.default.networkInterfaces(),
        uptime: os_1.default.uptime()
    };
}
//# sourceMappingURL=system.js.map