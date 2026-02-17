"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runSetup = runSetup;
const inquirer_1 = __importDefault(require("inquirer"));
const chalk_1 = __importDefault(require("chalk"));
const ora_1 = __importDefault(require("ora"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
const core_1 = require("@sentinel/core");
async function runSetup() {
    console.log(chalk_1.default.blue.bold('\n🛡️  SentinelAI Setup Wizard\n'));
    // Load existing config if available
    let config = { WATCH_FILES: [] }; // Initialize config here
    if (fs_1.default.existsSync(core_1.CONFIG_FILE)) {
        try {
            config = JSON.parse(fs_1.default.readFileSync(core_1.CONFIG_FILE, 'utf8'));
        }
        catch (e) { }
    }
    const POTENTIAL_LOGS = [
        // System
        '/var/log/syslog', '/var/log/messages', '/var/log/kern.log', '/var/log/auth.log', '/var/log/secure',
        '/var/log/boot.log', '/var/log/dmesg', '/var/log/daemon.log', '/var/log/faillog', '/var/log/wtmp',
        // Web
        '/var/log/nginx/access.log', '/var/log/nginx/error.log',
        '/var/log/apache2/access.log', '/var/log/apache2/error.log',
        '/var/log/httpd/access_log', '/var/log/httpd/error_log',
        // DB
        '/var/log/mysql/error.log', '/var/log/mysql/mysql.log', '/var/log/mysqld.log',
        '/var/log/mariadb/mariadb.log',
        // Common
        '/tmp/debug.log', '/tmp/error.log',
        // Custom
        '/home/antigravity/sentinelctl/web.log',
        '/home/antigravity/sentinelctl/test.log'
    ];
    // Dynamic Discovery for PHP and others
    const discoveryRoots = [
        '/var/log',
        '/var/www',
        '/home',
        '/usr/local/var/log', // Homebrew etc
    ];
    const detectedLogsSet = new Set();
    const scanLogsRecursive = (dir, depth = 0) => {
        if (depth > 4)
            return; // Limit depth to prevent performance issues
        if (!fs_1.default.existsSync(dir) || !fs_1.default.statSync(dir).isDirectory())
            return;
        // Skip sensitive or massive directories
        const basename = path_1.default.basename(dir);
        if (basename.startsWith('.') || basename === 'node_modules' || basename === 'vendor' || basename === 'cache')
            return;
        try {
            const items = fs_1.default.readdirSync(dir);
            items.forEach(item => {
                const fullPath = path_1.default.join(dir, item);
                try {
                    const stats = fs_1.default.statSync(fullPath);
                    if (stats.isFile()) {
                        const lower = item.toLowerCase();
                        // 1. Freshness Check (30 days)
                        const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
                        if (stats.mtimeMs < thirtyDaysAgo)
                            return;
                        // 2. Strict Identification: Must end in .log or be a core system log
                        const endsWithLog = lower.endsWith(".log");
                        const isCore = lower === "syslog" || lower === "auth.log" || lower === "kern.log" || lower === "secure";
                        // 3. Exclusion Filters
                        const isCompressed = lower.endsWith(".gz") || lower.endsWith(".zip") || lower.endsWith(".tar");
                        const isRotated = /\.\d+$/.test(lower) || lower.includes(".log.");
                        const isBackup = lower.includes(".bak") || lower.includes(".old") || lower.includes(".backup") || lower.includes("-202");
                        if ((endsWithLog || isCore) && !isCompressed && !isRotated && !isBackup) {
                            detectedLogsSet.add(fullPath);
                        }
                    }
                    else if (stats.isDirectory()) {
                        scanLogsRecursive(fullPath, depth + 1);
                    }
                }
                catch (e) { }
            });
        }
        catch (e) { }
    };
    // Check static list
    POTENTIAL_LOGS.forEach(p => {
        if (fs_1.default.existsSync(p))
            detectedLogsSet.add(p);
    });
    // Run recursive scan on roots
    discoveryRoots.forEach(root => scanLogsRecursive(root));
    const detectedLogs = Array.from(detectedLogsSet).sort();
    // Add custom option
    const logChoices = detectedLogs.map(l => ({ name: l, checked: true }));
    logChoices.push({ name: 'Enter Custom Path...', checked: false });
    // Gather System Info for AI context
    const sysInfo = {
        hostname: os_1.default.hostname(),
        platform: os_1.default.platform(),
        release: os_1.default.release(),
        type: os_1.default.type(),
        arch: os_1.default.arch(),
        cpus: os_1.default.cpus().length,
        memory: Math.round(os_1.default.totalmem() / (1024 * 1024 * 1024)) + 'GB'
    };
    console.log(chalk_1.default.blue(`\n🔍 Detected System: ${sysInfo.type} ${sysInfo.release} (${sysInfo.arch})`));
    console.log(chalk_1.default.blue(`   Scanning for logs... Found ${detectedLogs.length} potential log files.\n`));
    const questions = [
        {
            type: 'confirm',
            name: 'clearConfig',
            message: 'Do you want to clear your existing monitored files list before starting?',
            default: false
        },
        {
            type: 'list',
            name: 'aiProvider',
            message: 'Select AI Provider:',
            choices: [
                { name: 'Google Gemini', value: 'gemini' },
                { name: 'OpenAI', value: 'openai' },
                { name: 'Zhipu AI (GLM-4)', value: 'zhipu' },
                { name: 'Offline (Local Shield Only - No AI)', value: 'none' }
            ],
            default: config.AI_PROVIDER || 'gemini'
        },
        {
            type: 'input',
            name: 'geminiKey',
            message: 'Enter your Google Gemini API Key:',
            when: (answers) => answers.aiProvider === 'gemini',
            default: config.GEMINI_API_KEY || process.env.GEMINI_API_KEY || '',
        },
        {
            type: 'input',
            name: 'openaiKey',
            message: 'Enter your OpenAI API Key:',
            when: (answers) => answers.aiProvider === 'openai',
            default: config.OPENAI_API_KEY || process.env.OPENAI_API_KEY || '',
        },
        {
            type: 'input',
            name: 'zhipuKey',
            message: 'Enter your Zhipu GLM API Key:',
            when: (answers) => answers.aiProvider === 'zhipu',
            default: config.ZHIPU_API_KEY || process.env.ZHIPU_API_KEY || '',
        },
        {
            type: 'input',
            name: 'modelName',
            message: 'Enter Model Name (e.g., gemini-1.5-flash, gpt-4o, glm-4-plus, glm4.7):',
            when: (answers) => answers.aiProvider !== 'none',
            default: (answers) => {
                if (answers.aiProvider === 'gemini')
                    return config.GEMINI_MODEL || 'gemini-1.5-flash';
                if (answers.aiProvider === 'openai')
                    return config.OPENAI_MODEL || 'gpt-4o';
                if (answers.aiProvider === 'zhipu')
                    return config.ZHIPU_MODEL || 'glm-4-plus';
                return '';
            }
        },
        {
            type: 'input', // Using input because 'number' type can be flaky in some terminals
            name: 'startupScanLines',
            message: 'Startup Scan: How many existing log lines to check? (Default: 500, 0=None):',
            default: config.STARTUP_READ_LINES !== undefined ? config.STARTUP_READ_LINES : 500,
            validate: (input) => {
                const num = parseInt(input);
                if (isNaN(num) || num < 0 || num > 10000)
                    return 'Please enter a number between 0 and 10000.';
                return true;
            }
        },
        {
            type: 'checkbox',
            name: 'selectedLogs',
            message: 'Select log files to monitor:',
            choices: logChoices,
            validate: (answer) => {
                if (answer.length < 1)
                    return 'You must choose at least one log file.';
                return true;
            }
        },
        {
            type: 'input',
            name: 'customLogFile',
            message: 'Enter absolute path to custom log file:',
            when: (answers) => answers.selectedLogs.includes('Enter Custom Path...'),
            validate: (input) => {
                if (input && !fs_1.default.existsSync(input) && !input.startsWith('/tmp/')) {
                    return 'File does not exist (unless creating a temp test file).';
                }
                return true;
            }
        },
        {
            type: 'confirm',
            name: 'enableCloud',
            message: chalk_1.default.magenta('Connect to Sentinel Cloud Dashboard? (Recommended)'),
            default: true
        },
        {
            type: 'input',
            name: 'cloudKey',
            message: (answers) => {
                console.log(chalk_1.default.cyan('\n💡 Sentinel Cloud allows you to monitor this server from anywhere.'));
                console.log(chalk_1.default.cyan(`🔗 Sign up or login at: ${chalk_1.default.bold('https://proactive-security-web.vercel.app/register')}\n`));
                return 'Enter your Sentinel Agent Key (Found in Dashboard -> Settings):';
            },
            when: (answers) => answers.enableCloud,
            default: config.SENTINEL_AGENT_KEY || '',
        },
        {
            type: 'confirm',
            name: 'enableTelegram',
            message: chalk_1.default.yellow('Enable Telegram Notifications? (Ensure the Sentinel Agent is STOPPED first)'),
            default: !!config.TELEGRAM_BOT_TOKEN
        },
        {
            type: 'input',
            name: 'telegramToken',
            message: 'Enter Telegram Bot Token:',
            when: (answers) => answers.enableTelegram,
            default: config.TELEGRAM_BOT_TOKEN || '',
            validate: (input) => input.length > 10 || 'Token seems too short.'
        },
        // ── Cloudflare Configuration (Optional) ──────────────────
        {
            type: 'confirm',
            name: 'behindCloudflare',
            message: chalk_1.default.yellow('Are you behind Cloudflare? (Enables smart IP blocking)'),
            default: !!config.CF_API_TOKEN || !!config.CF_ZONE_ID
        },
        {
            type: 'input',
            name: 'cfApiToken',
            message: (answers) => {
                console.log(chalk_1.default.cyan('\n☁️  Cloudflare API Token allows global IP blocking.'));
                console.log(chalk_1.default.cyan('   Create one at: https://dash.cloudflare.com/profile/api-tokens'));
                console.log(chalk_1.default.cyan('   Required permissions: Account > Account Firewall Access Rules > Edit'));
                console.log(chalk_1.default.dim('   Leave blank to use Nginx/Apache deny rules as fallback.\n'));
                return 'Enter Cloudflare API Token (optional):';
            },
            when: (answers) => answers.behindCloudflare,
            default: config.CF_API_TOKEN || '',
        },
        {
            type: 'input',
            name: 'cfZoneId',
            message: 'Enter Cloudflare Zone ID (found on your domain\'s overview page):',
            when: (answers) => answers.behindCloudflare && answers.cfApiToken,
            default: config.CF_ZONE_ID || '',
            validate: (input) => input.length > 10 || 'Zone ID seems too short (check your Cloudflare dashboard).'
        },
    ];
    const answers = await inquirer_1.default.prompt(questions);
    const spinner = (0, ora_1.default)('Configuring SentinelAI...').start();
    if (answers.clearConfig) {
        config.WATCH_FILES = [];
        (0, core_1.log)(chalk_1.default.dim('Existing monitored files cleared.'));
    }
    if (answers.aiProvider) {
        config.AI_PROVIDER = answers.aiProvider;
    }
    if (answers.geminiKey) {
        config.GEMINI_API_KEY = answers.geminiKey;
    }
    if (answers.openaiKey) {
        config.OPENAI_API_KEY = answers.openaiKey;
    }
    if (answers.zhipuKey) {
        config.ZHIPU_API_KEY = answers.zhipuKey;
    }
    if (answers.modelName) {
        if (config.AI_PROVIDER === 'openai') {
            config.OPENAI_MODEL = answers.modelName;
        }
        else if (config.AI_PROVIDER === 'zhipu') {
            config.ZHIPU_MODEL = answers.modelName;
        }
        else {
            config.GEMINI_MODEL = answers.modelName;
        }
    }
    if (answers.startupScanLines !== undefined) {
        config.STARTUP_READ_LINES = parseInt(answers.startupScanLines);
    }
    if (answers.selectedLogs) {
        config.WATCH_FILES = config.WATCH_FILES || [];
        answers.selectedLogs.forEach((log) => {
            if (log !== 'Enter Custom Path...' && !config.WATCH_FILES.includes(log)) {
                config.WATCH_FILES.push(log);
            }
        });
    }
    if (answers.customLogFile) {
        if (!config.WATCH_FILES.includes(answers.customLogFile)) {
            config.WATCH_FILES.push(answers.customLogFile);
        }
    }
    if (answers.cloudKey) {
        config.SENTINEL_AGENT_KEY = answers.cloudKey;
        // Also set the Cloud URL by default if key is provided
        config.SENTINEL_CLOUD_URL = "https://proactive-security-web.vercel.app";
    }
    // Cloudflare API Configuration
    if (answers.behindCloudflare) {
        if (answers.cfApiToken && answers.cfZoneId) {
            config.CF_API_TOKEN = answers.cfApiToken;
            config.CF_ZONE_ID = answers.cfZoneId;
            console.log(chalk_1.default.green('\n☁️  Cloudflare API blocking configured — attackers will be blocked globally.'));
        }
        else {
            // Remove any old CF config if user chose not to provide keys
            delete config.CF_API_TOKEN;
            delete config.CF_ZONE_ID;
            console.log(chalk_1.default.yellow('\n☁️  No CF API key — agent will use Nginx/Apache deny rules behind Cloudflare.'));
        }
    }
    else {
        delete config.CF_API_TOKEN;
        delete config.CF_ZONE_ID;
    }
    // Save System Info
    config.SYSTEM_INFO = sysInfo;
    if (answers.enableTelegram) {
        config.TELEGRAM_BOT_TOKEN = answers.telegramToken;
        // Auto-detect Chat ID
        const Spinner = (0, ora_1.default)('Waiting for you to message the bot...').start();
        console.log(chalk_1.default.yellow('\n\n👉 Action Required: Open your bot in Telegram and send /start'));
        try {
            // Poll for updates
            let chatId = '';
            let retries = 0;
            const maxRetries = 30; // 30 * 2s = 60s
            while (!chatId && retries < maxRetries) {
                Spinner.text = `Waiting for you to message the bot... (${maxRetries - retries}s remaining)`;
                await new Promise(r => setTimeout(r, 2000));
                try {
                    // Use global fetch (Node 18+) or fallback to require
                    const fetcher = typeof fetch !== 'undefined' ? fetch : require('node-fetch');
                    const response = await fetcher(`https://api.telegram.org/bot${answers.telegramToken}/getUpdates?timeout=5`);
                    const data = await response.json();
                    if (data.ok && data.result && data.result.length > 0) {
                        // Find the last message or member update
                        for (let i = data.result.length - 1; i >= 0; i--) {
                            const update = data.result[i];
                            const potentialId = update.message?.chat?.id || update.my_chat_member?.chat?.id || update.callback_query?.message?.chat?.id;
                            if (potentialId) {
                                chatId = String(potentialId);
                                break;
                            }
                        }
                    }
                    else if (!data.ok) {
                        (0, core_1.log)(chalk_1.default.dim(`\n⚠️ Telegram API Error: ${data.description}`));
                    }
                }
                catch (err) {
                    // console.error(err);
                }
                retries++;
            }
            if (chatId) {
                config.TELEGRAM_CHAT_ID = chatId;
                Spinner.succeed(`Found Chat ID: ${chatId}`);
                // Send Welcome Message and Set Commands
                try {
                    const fetcher = typeof fetch !== 'undefined' ? fetch : require('node-fetch');
                    const welcomeMsg = encodeURIComponent("🛡️ *SentinelAI Setup Complete!*\n\nI am now linked to this server. I will notify you of any security threats in real-time.\n\nUse the menu or type /help to see what I can do.");
                    await fetcher(`https://api.telegram.org/bot${answers.telegramToken}/sendMessage?chat_id=${chatId}&text=${welcomeMsg}&parse_mode=Markdown`);
                    // Set Bot Commands Menu
                    const commands = JSON.stringify([
                        { command: 'status', description: 'Check server security status' },
                        { command: 'stats', description: 'View AI analysis statistics' },
                        { command: 'banned', description: 'List currently banned IPs' },
                        { command: 'help', description: 'Show available commands' }
                    ]);
                    await fetcher(`https://api.telegram.org/bot${answers.telegramToken}/setMyCommands?commands=${encodeURIComponent(commands)}`);
                }
                catch (e) {
                    (0, core_1.log)(chalk_1.default.dim(`\n⚠️ Failed to send welcome message: ${e}`));
                }
            }
            else {
                Spinner.warn('Timed out waiting for message.');
                console.log(chalk_1.default.dim('You can find your Chat ID using @userinfobot and set it manually in ~/.sentinel/config.json'));
            }
        }
        catch (e) {
            Spinner.fail('Failed to auto-detect Chat ID.');
        }
    }
    // Auto-Whitelist Local IPs
    config.WHITELIST_IPS = config.WHITELIST_IPS || [];
    const whitelistSet = new Set(config.WHITELIST_IPS);
    whitelistSet.add("127.0.0.1");
    whitelistSet.add("::1");
    const nets = os_1.default.networkInterfaces();
    for (const name of Object.keys(nets)) {
        for (const net of nets[name] || []) {
            if (!net.internal) {
                whitelistSet.add(net.address);
            }
        }
    }
    config.WHITELIST_IPS = Array.from(whitelistSet);
    console.log(chalk_1.default.blue(`\n🛡️  Auto-whitelisted ${config.WHITELIST_IPS.length} local IPs for safety.`));
    fs_1.default.writeFileSync(core_1.CONFIG_FILE, JSON.stringify(config, null, 2));
    await new Promise(resolve => setTimeout(resolve, 1000)); // Fake delight
    spinner.succeed('Configuration saved!');
    console.log('\n' + chalk_1.default.green('✔ Setup Complete!'));
    console.log(chalk_1.default.cyan('Run `sentinelctl start` to launch the agent.'));
}
//# sourceMappingURL=setup.js.map