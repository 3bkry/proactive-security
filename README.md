
# 🛡️ SentinelAI - Proactive Security Agent

<div align="center">

![SentinelAI](https://via.placeholder.com/800x400?text=SentinelAI+Active+Defense)

**Automated Threat Detection & Response System powered by Gemini 3.0**

[![GitHub](https://img.shields.io/badge/GitHub-Repo-blue?logo=github)](https://github.com/3bkry/proactive-security)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-Active-success)](https://github.com/3bkry/proactive-security)

</div>

## 🚀 One-Line Installation

Install SentinelAI on any Linux server instantly:

```bash
curl -fsSL https://raw.githubusercontent.com/3bkry/proactive-security/main/install.sh | sudo bash
```

---

## ⚡ Key Features

- **🧠 Gemini 3.0 Powered Analysis**: Uses Google's latest AI model to analyze logs in real-time with SRE-level precision.
- **🛡️ Active Defense**: Automatically bans malicious IPs using `iptables` when high-risk threats (SSH brute force, SQLi, etc.) are detected.
- **📱 Telegram Integration**: Get instant alerts and control your server from anywhere. Includes **One-Click Unban** buttons.
- **🔍 Deep Log Inspection**: Monitors `syslog`, `auth.log`, `nginx`, `PM2`, and more.
- **📊 Real-Time Dashboard**: Visualize threats, system status, and AI insights.

## 🛠️ Usage

### Quick Start
After installation, run the setup wizard to configure your API keys and Telegram bot:

```bash
sentinelctl setup
```

### Commands

| Command | Description |
|---------|-------------|
| `sentinelctl start` | Launch the Agent and Dashboard |
| `sentinelctl stop`  | Stop all SentinelAI services |
| `sentinelctl ban <ip>` | Manually ban an IP address (globally) |
| `sentinelctl watch <file>` | Add a new log file to monitor |

### Telegram Bot Commands

- `/status` - View server health (CPU, RAM, Uptime)
- `/stats` - View AI usage and costs
- `/banned` - List currently blocked IPs
- **Interactive Alerts**: Tap "🚫 Ban" or "🔓 Unban" directly on alert messages.

## 🏗️ Architecture

SentinelAI consists of three main components:

1.  **Core Agent**: A Node.js background service that tails logs and manages the defense system.
2.  **AI Engine**: Integated with Google Gemini 3.0 Flash Preview for intelligent threat analysis.
3.  **CLI (sentinelctl)**: A powerful command-line interface for management.

## 🔒 Security Note and System Paths

- **Installation**: Installs to `/opt/sentinel-agent`.
- **Config**: `/etc/sentinel-agent/config.json`
- **Logs**: `/var/log/sentinel-agent/`
- **Permissions**: Defines a `sentinel` group and adds your user to it.
- **Sudo**: Configures `/etc/sudoers.d/sentinel-ban` to allow the `sentinel` group to run `iptables` without a password (required for active defense).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

<div align="center">
Built with ❤️ for the Security Community
</div>
