"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const core_1 = require("@sentinel/core");
const child_process_1 = require("child_process");
const path_1 = __importDefault(require("path"));
const program = new commander_1.Command();
const fs_1 = __importDefault(require("fs"));
// Load .env manually if present
const envPath = path_1.default.resolve(__dirname, '../../../.env');
if (fs_1.default.existsSync(envPath)) {
    const envConfig = fs_1.default.readFileSync(envPath, 'utf8');
    envConfig.split('\n').forEach(line => {
        const match = line.match(/^([^=]+)=(.*)$/);
        if (match) {
            const key = match[1].trim();
            const value = match[2].trim().replace(/^"(.*)"$/, '$1');
            if (!process.env[key]) {
                process.env[key] = value;
            }
        }
    });
}
program
    .name('sentinelctl')
    .description('Control SentinelAI Security Agent')
    .version('0.1.0');
const setup_1 = require("./setup");
program
    .command('setup')
    .description('Run interactive onboarding wizard')
    .action(async () => {
    await (0, setup_1.runSetup)();
});
program
    .command('start')
    .description('Start the Sentinel Agent and Dashboard')
    .option('--safe', 'Start agent in Safe Mode (Observer Only)')
    .action((options) => {
    const isCloud = !!process.env.SENTINEL_CLOUD_URL;
    console.log(isCloud ? '🚀 Starting SentinelAI Agent in Cloud Mode...' : '🚀 Starting SentinelAI (Local Mode)...');
    if (options.safe) {
        console.log('🛡️ ENABLED SAFE MODE: Active enforcement disabled.');
    }
    const rootDir = path_1.default.resolve(__dirname, '../../..');
    const agentArgs = ['start', '-w', 'apps/agent'];
    if (options.safe) {
        agentArgs.push('--');
        agentArgs.push('--safe');
    }
    const agent = (0, child_process_1.spawn)('npm', agentArgs, {
        cwd: rootDir,
        stdio: 'inherit',
        env: { ...process.env, PORT: '8081' }
    });
    if (!isCloud) {
        const web = (0, child_process_1.spawn)('npm', ['run', 'dev', '-w', 'apps/web'], {
            cwd: rootDir,
            stdio: 'inherit'
        });
        // Open browser after a slight delay
        setTimeout(() => {
            const url = 'http://localhost:3000';
            const start = (process.platform == 'darwin' ? 'open' : process.platform == 'win32' ? 'start' : 'xdg-open');
            (0, child_process_1.spawn)(start, [url]);
            console.log(`\nDashboard opened at ${url}`);
        }, 3000);
        // Cleanup on exit
        process.on('SIGINT', () => {
            agent.kill();
            web.kill();
            process.exit();
        });
    }
    else {
        console.log(`\n📡 Agent is connecting to: ${process.env.SENTINEL_CLOUD_URL}`);
        console.log(`🔗 Monitor your server at: ${process.env.SENTINEL_CLOUD_URL}`);
        process.on('SIGINT', () => {
            agent.kill();
            process.exit();
        });
    }
});
program
    .command('stop')
    .description('Stop the Sentinel Agent and Dashboard')
    .action(() => {
    const { execSync } = require('child_process');
    console.log('🛑 Stopping all SentinelAI services...');
    try {
        // Kill processes on ports 3000 (web) and any port in the 8081-8100 range (agent)
        // also kill anything matched by binary name/path
        execSync('fuser -k 3000/tcp 2>/dev/null || true');
        execSync('fuser -k 8081/tcp 8082/tcp 8083/tcp 8084/tcp 8085/tcp 2>/dev/null || true');
        // Kill any node processes running our agent or web app
        try {
            execSync('pkill -f "apps/agent/dist/index.js" || true');
            execSync('pkill -f "apps/web/.next" || true');
        }
        catch (e) { }
        console.log('✅ Services stopped successfully.');
    }
    catch (e) {
        console.error('❌ Failed to stop services cleanly.');
    }
});
program
    .command('ban <ip>')
    .description('Manually ban an IP address (Requires ROOT)')
    .action((ip) => {
    const { execSync } = require('child_process');
    console.log(`🛡️ Banning IP: ${ip}...`);
    try {
        // Check for root
        if (process.getuid && process.getuid() !== 0) {
            console.warn('⚠️ Warning: This command usually requires root privileges (sudo).');
        }
        // Apply iptables rule
        execSync(`iptables -A INPUT -s ${ip} -j DROP`);
        console.log(`✅ IP ${ip} has been blocked via iptables.`);
    }
    catch (e) {
        console.error(`❌ Failed to ban IP: ${e.message}`);
        console.log('Ensure you are running this as root/sudo.');
    }
});
program
    .command('config <key> <value>')
    .description('Manage configuration')
    .action((key, value) => {
    // TODO: Implement actual config storage
    console.log(`Setting ${key} = ${value}`);
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    // Simple config file in home dir for now
    // const configDir = path.join(os.homedir(), '.sentinel');
    // if (!fs.existsSync(configDir)) fs.mkdirSync(configDir, { recursive: true });
    const configFile = core_1.CONFIG_FILE;
    let config = {};
    if (fs.existsSync(configFile)) {
        try {
            config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
        }
        catch (e) { }
    }
    config[key] = value;
    fs.writeFileSync(configFile, JSON.stringify(config, null, 2));
    (0, core_1.log)(`Configuration saved to ${configFile}`);
});
program
    .command('watch <path>')
    .description('Add a log file or directory (recursive) to be monitored')
    .action((inputPath) => {
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const absPath = path.resolve(inputPath);
    if (!fs.existsSync(absPath)) {
        console.error(`Error: Path does not exist: ${absPath}`);
        process.exit(1);
    }
    const configFile = core_1.CONFIG_FILE;
    let config = {};
    if (fs.existsSync(configFile)) {
        try {
            config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
        }
        catch (e) { }
    }
    const watchList = config.WATCH_FILES || [];
    const addedFiles = [];
    const addFile = (p) => {
        if (!watchList.includes(p)) {
            watchList.push(p);
            addedFiles.push(p);
        }
    };
    const scanRecursive = (dir, depth = 0) => {
        if (depth > 3)
            return;
        const items = fs.readdirSync(dir);
        items.forEach((item) => {
            const fullPath = path.join(dir, item);
            const stats = fs.statSync(fullPath);
            if (stats.isFile() && item.endsWith('.log')) {
                addFile(fullPath);
            }
            else if (stats.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
                scanRecursive(fullPath, depth + 1);
            }
        });
    };
    const stats = fs.statSync(absPath);
    if (stats.isFile()) {
        addFile(absPath);
    }
    else if (stats.isDirectory()) {
        console.log(`🔍 Scanning directory recursively: ${absPath}`);
        scanRecursive(absPath);
    }
    if (addedFiles.length > 0) {
        config.WATCH_FILES = watchList;
        fs.writeFileSync(configFile, JSON.stringify(config, null, 2));
        (0, core_1.log)(`Added ${addedFiles.length} file(s) to watch list.`);
        if (addedFiles.length < 10) {
            addedFiles.forEach(f => (0, core_1.log)(`  + ${f}`));
        }
        (0, core_1.log)(`Restart agent to apply changes: sentinelctl start`);
    }
    else {
        (0, core_1.log)(`No new .log files found to watch.`);
    }
});
program.parse(process.argv);
//# sourceMappingURL=index.js.map