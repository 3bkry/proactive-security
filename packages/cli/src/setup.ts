
import inquirer from 'inquirer';
import figlet from 'figlet';
import chalk from 'chalk';
import ora from 'ora';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { log, SENTINEL_CONFIG_DIR, CONFIG_FILE } from '@sentinel/core';

export async function runSetup() {
    console.log(chalk.blue.bold('\n🛡️  SentinelAI Setup Wizard\n'));

    // Load existing config if available
    let config: any = { WATCH_FILES: [] }; // Initialize config here
    if (fs.existsSync(CONFIG_FILE)) {
        try {
            config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
        } catch (e) { }
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

    const detectedLogsSet = new Set<string>();

    const scanLogsRecursive = (dir: string, depth = 0) => {
        if (depth > 4) return; // Limit depth to prevent performance issues
        if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) return;

        // Skip sensitive or massive directories
        const basename = path.basename(dir);
        if (basename.startsWith('.') || basename === 'node_modules' || basename === 'vendor' || basename === 'cache') return;

        try {
            const items = fs.readdirSync(dir);
            items.forEach(item => {
                const fullPath = path.join(dir, item);
                try {
                    const stats = fs.statSync(fullPath);
                    if (stats.isFile()) {
                        const lower = item.toLowerCase();

                        // 1. Freshness Check (30 days)
                        const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
                        if (stats.mtimeMs < thirtyDaysAgo) return;

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
                    } else if (stats.isDirectory()) {
                        scanLogsRecursive(fullPath, depth + 1);
                    }
                } catch (e) { }
            });
        } catch (e) { }
    };

    // Check static list
    POTENTIAL_LOGS.forEach(p => {
        if (fs.existsSync(p)) detectedLogsSet.add(p);
    });

    // Run recursive scan on roots
    discoveryRoots.forEach(root => scanLogsRecursive(root));

    const detectedLogs = Array.from(detectedLogsSet).sort();
    // Add custom option
    const logChoices = detectedLogs.map(l => ({ name: l, checked: true }));
    logChoices.push({ name: 'Enter Custom Path...', checked: false });

    // Gather System Info for AI context
    const sysInfo = {
        hostname: os.hostname(),
        platform: os.platform(),
        release: os.release(),
        type: os.type(),
        arch: os.arch(),
        cpus: os.cpus().length,
        memory: Math.round(os.totalmem() / (1024 * 1024 * 1024)) + 'GB'
    };

    console.log(chalk.blue(`\n🔍 Detected System: ${sysInfo.type} ${sysInfo.release} (${sysInfo.arch})`));
    console.log(chalk.blue(`   Scanning for logs... Found ${detectedLogs.length} potential log files.\n`));

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
                { name: 'Zhipu AI (GLM-4)', value: 'zhipu' }
            ],
            default: config.AI_PROVIDER || 'gemini'
        },
        {
            type: 'input',
            name: 'geminiKey',
            message: 'Enter your Google Gemini API Key:',
            when: (answers: any) => answers.aiProvider === 'gemini',
            default: config.GEMINI_API_KEY || process.env.GEMINI_API_KEY || '',
        },
        {
            type: 'input',
            name: 'openaiKey',
            message: 'Enter your OpenAI API Key:',
            when: (answers: any) => answers.aiProvider === 'openai',
            default: config.OPENAI_API_KEY || process.env.OPENAI_API_KEY || '',
        },
        {
            type: 'input',
            name: 'zhipuKey',
            message: 'Enter your Zhipu GLM API Key:',
            when: (answers: any) => answers.aiProvider === 'zhipu',
            default: config.ZHIPU_API_KEY || process.env.ZHIPU_API_KEY || '',
        },
        {
            type: 'input',
            name: 'modelName',
            message: 'Enter Model Name (e.g., gemini-1.5-flash, gpt-4o, glm-4-plus, glm4.7):',
            default: (answers: any) => {
                if (answers.aiProvider === 'gemini') return config.GEMINI_MODEL || 'gemini-1.5-flash';
                if (answers.aiProvider === 'openai') return config.OPENAI_MODEL || 'gpt-4o';
                if (answers.aiProvider === 'zhipu') return config.ZHIPU_MODEL || 'glm-4-plus';
                return '';
            }
        },
        {
            type: 'checkbox',
            name: 'selectedLogs',
            message: 'Select log files to monitor:',
            choices: logChoices,
            validate: (answer: string[]) => {
                if (answer.length < 1) return 'You must choose at least one log file.';
                return true;
            }
        },
        {
            type: 'input',
            name: 'customLogFile',
            message: 'Enter absolute path to custom log file:',
            when: (answers: any) => answers.selectedLogs.includes('Enter Custom Path...'),
            validate: (input: string) => {
                if (input && !fs.existsSync(input) && !input.startsWith('/tmp/')) {
                    return 'File does not exist (unless creating a temp test file).';
                }
                return true;
            }
        },
        {
            type: 'confirm',
            name: 'enableCloud',
            message: chalk.magenta('Connect to Sentinel Cloud Dashboard? (Recommended)'),
            default: true
        },
        {
            type: 'input',
            name: 'cloudKey',
            message: (answers: any) => {
                console.log(chalk.cyan('\n💡 Sentinel Cloud allows you to monitor this server from anywhere.'));
                console.log(chalk.cyan(`🔗 Sign up or login at: ${chalk.bold('https://proactive-security-web.vercel.app/register')}\n`));
                return 'Enter your Sentinel Agent Key (Found in Dashboard -> Settings):';
            },
            when: (answers: any) => answers.enableCloud,
            default: config.SENTINEL_AGENT_KEY || '',
        },
        {
            type: 'confirm',
            name: 'enableTelegram',
            message: chalk.yellow('Enable Telegram Notifications? (Ensure the Sentinel Agent is STOPPED first)'),
            default: !!config.TELEGRAM_BOT_TOKEN
        },
        {
            type: 'input',
            name: 'telegramToken',
            message: 'Enter Telegram Bot Token:',
            when: (answers: any) => answers.enableTelegram,
            default: config.TELEGRAM_BOT_TOKEN || '',
            validate: (input: string) => input.length > 10 || 'Token seems too short.'
        }
    ];

    const answers = await inquirer.prompt(questions);

    const spinner = ora('Configuring SentinelAI...').start();

    if (answers.clearConfig) {
        config.WATCH_FILES = [];
        log(chalk.dim('Existing monitored files cleared.'));
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
        } else if (config.AI_PROVIDER === 'zhipu') {
            config.ZHIPU_MODEL = answers.modelName;
        } else {
            config.GEMINI_MODEL = answers.modelName;
        }
    }

    if (answers.selectedLogs) {
        config.WATCH_FILES = config.WATCH_FILES || [];
        answers.selectedLogs.forEach((log: string) => {
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

    // Save System Info
    config.SYSTEM_INFO = sysInfo;

    if (answers.enableTelegram) {
        config.TELEGRAM_BOT_TOKEN = answers.telegramToken;

        // Auto-detect Chat ID
        const Spinner = ora('Waiting for you to message the bot...').start();
        console.log(chalk.yellow('\n\n👉 Action Required: Open your bot in Telegram and send /start'));

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
                    } else if (!data.ok) {
                        log(chalk.dim(`\n⚠️ Telegram API Error: ${data.description}`));
                    }
                } catch (err) {
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
                } catch (e) {
                    log(chalk.dim(`\n⚠️ Failed to send welcome message: ${e}`));
                }
            } else {
                Spinner.warn('Timed out waiting for message.');
                console.log(chalk.dim('You can find your Chat ID using @userinfobot and set it manually in ~/.sentinel/config.json'));
            }
        } catch (e) {
            Spinner.fail('Failed to auto-detect Chat ID.');
        }
    }

    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));

    await new Promise(resolve => setTimeout(resolve, 1000)); // Fake delight
    spinner.succeed('Configuration saved!');

    console.log('\n' + chalk.green('✔ Setup Complete!'));
    console.log(chalk.cyan('Run `sentinelctl start` to launch the agent.'));
}
