import { Command } from 'commander';
import { log, CONFIG_FILE } from '@sentinel/core';
import { spawn } from 'child_process';
import path from 'path';

const program = new Command();
import fs from 'fs';

// Load .env manually if present
const envPath = path.resolve(__dirname, '../../../.env');
if (fs.existsSync(envPath)) {
    const envConfig = fs.readFileSync(envPath, 'utf8');
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

import { runSetup } from './setup';

program
    .command('setup')
    .description('Run interactive onboarding wizard')
    .action(async () => {
        await runSetup();
    });

program
    .command('start')
    .description('Start the Sentinel Agent and Dashboard')
    .action(() => {
        const isCloud = !!process.env.SENTINEL_CLOUD_URL;
        console.log(isCloud ? '🚀 Starting SentinelAI Agent in Cloud Mode...' : '🚀 Starting SentinelAI (Local Mode)...');
        const rootDir = path.resolve(__dirname, '../../..');

        const agent = spawn('npm', ['start', '-w', 'apps/agent'], {
            cwd: rootDir,
            stdio: 'inherit',
            env: { ...process.env, PORT: '8081' }
        });

        if (!isCloud) {
            const web = spawn('npm', ['run', 'dev', '-w', 'apps/web'], {
                cwd: rootDir,
                stdio: 'inherit'
            });

            // Open browser after a slight delay
            setTimeout(() => {
                const url = 'http://localhost:3000';
                const start = (process.platform == 'darwin' ? 'open' : process.platform == 'win32' ? 'start' : 'xdg-open');
                spawn(start, [url]);
                console.log(`\nDashboard opened at ${url}`);
            }, 3000);

            // Cleanup on exit
            process.on('SIGINT', () => {
                agent.kill();
                web.kill();
                process.exit();
            });
        } else {
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
            } catch (e) { }

            console.log('✅ Services stopped successfully.');
        } catch (e) {
            console.error('❌ Failed to stop services cleanly.');
        }
    });

program
    .command('ban <ip>')
    .description('Manually ban an IP address (Requires ROOT)')
    .action((ip: string) => {
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
        } catch (e: any) {
            console.error(`❌ Failed to ban IP: ${e.message}`);
            console.log('Ensure you are running this as root/sudo.');
        }
    });



program
    .command('config <key> <value>')
    .description('Manage configuration')
    .action((key: string, value: string) => {
        // TODO: Implement actual config storage
        console.log(`Setting ${key} = ${value}`);
        const fs = require('fs');
        const os = require('os');
        const path = require('path');

        // Simple config file in home dir for now
        // const configDir = path.join(os.homedir(), '.sentinel');
        // if (!fs.existsSync(configDir)) fs.mkdirSync(configDir, { recursive: true });

        const configFile = CONFIG_FILE;
        let config: any = {};
        if (fs.existsSync(configFile)) {
            try {
                config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
            } catch (e) { }
        }

        config[key] = value;
        fs.writeFileSync(configFile, JSON.stringify(config, null, 2));
        log(`Configuration saved to ${configFile}`);
    });

program
    .command('watch <file>')
    .description('Add a log file to be monitored')
    .action((file: string) => {
        const fs = require('fs');
        const os = require('os');
        const path = require('path');

        const absPath = path.resolve(file);
        if (!fs.existsSync(absPath)) {
            console.error(`Error: File does not exist: ${absPath}`);
            process.exit(1);
        }

        const configDir = path.join(os.homedir(), '.sentinel');
        if (!fs.existsSync(configDir)) fs.mkdirSync(configDir, { recursive: true });

        const configFile = path.join(configDir, 'config.json');
        let config: any = {};
        if (fs.existsSync(configFile)) {
            try {
                config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
            } catch (e) { }
        }

        const watchList = config.WATCH_FILES || [];
        if (!watchList.includes(absPath)) {
            watchList.push(absPath);
            config.WATCH_FILES = watchList;
            fs.writeFileSync(configFile, JSON.stringify(config, null, 2));
            log(`Added ${absPath} to watch list.`);
            log(`Restart agent to apply changes: sentinelctl start`);
        } else {
            log(`${absPath} is already being watched.`);
        }
    });

program.parse(process.argv);
