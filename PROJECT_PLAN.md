# SentinelAI — Full Project Plan

## AI-Powered Server & Website Security Platform

**Version**: 1.0.0-planning
**Date**: 2026-02-09
**License**: AGPL-3.0 (agent) / BSL 1.1 (cloud)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Tech Stack](#2-tech-stack)
3. [System Architecture](#3-system-architecture)
4. [Repository Structure](#4-repository-structure)
5. [Agent Core Design](#5-agent-core-design)
6. [AI Detection Engine](#6-ai-detection-engine)
7. [CLI Interface](#7-cli-interface)
8. [Database Schemas](#8-database-schemas)
9. [API Contracts](#9-api-contracts)
10. [Bot Integrations](#10-bot-integrations)
11. [Cloud SaaS Platform](#11-cloud-saas-platform)
12. [Web Dashboard](#12-web-dashboard)
13. [Configuration System](#13-configuration-system)
14. [Installation & Packaging](#14-installation--packaging)
15. [Security Model](#15-security-model)
16. [Implementation Phases](#16-implementation-phases)
17. [Deployment Plan](#17-deployment-plan)

---

## 1. Project Overview

SentinelAI is a Linux-first, open-source security agent that monitors server and application logs in real time, detects threats using a hybrid AI engine (rules + anomaly detection + optional LLM), automatically responds to attacks, and reports through CLI, bots, and an optional cloud dashboard.

### Design Principles

- **Offline-first**: Agent works fully without internet or cloud
- **Explainability**: Every block action includes a reason and risk score
- **Minimal footprint**: Agent idles under 50MB RAM, <2% CPU
- **Fail-safe**: If AI is uncertain, alert — never auto-block
- **Privacy-first**: No logs leave the server unless user opts in
- **Composable**: Each subsystem (monitor, detector, responder, notifier) is independent

---

## 2. Tech Stack

### Agent (Local)

| Component | Technology | Reason |
|-----------|-----------|--------|
| Language | **Python 3.11+** | Ecosystem for AI/ML, fast prototyping, Linux-native |
| Process manager | **systemd** | Standard Linux service management |
| Log tailing | **pyinotify** + polling fallback | Real-time file watching |
| Database | **SQLite** (local) | Zero-config, single-file, production-viable |
| Task scheduling | **APScheduler** | In-process cron-like scheduling |
| Firewall control | **subprocess** → iptables/nftables/ufw | Direct system calls with abstraction layer |
| CLI framework | **Click** | Clean, composable CLI with auto-help |
| Config format | **YAML** (primary) + JSON (export) | Human-readable, widely understood |
| AI/ML | **scikit-learn** + **regex** + optional **ollama/OpenAI** | Hybrid detection without heavy deps |
| Packaging | **pip** + **deb** + **rpm** + **install.sh** | Multiple install paths |

### Cloud SaaS

| Component | Technology | Reason |
|-----------|-----------|--------|
| Backend API | **FastAPI** (Python) | Async, typed, same language as agent |
| Database | **PostgreSQL** | Multi-tenant, scalable |
| Cache / Queue | **Redis** + **Celery** | Real-time pub/sub + background jobs |
| Auth | **JWT** + API keys | Stateless, agent-friendly |
| WebSocket | **FastAPI WebSockets** | Real-time dashboard updates |

### Dashboard

| Component | Technology | Reason |
|-----------|-----------|--------|
| Framework | **Next.js 14** (App Router) | SSR, API routes, React ecosystem |
| UI library | **shadcn/ui** + **Tailwind CSS** | Clean, dark-mode-ready components |
| Charts | **Recharts** | Lightweight, React-native |
| Real-time | **Socket.IO client** | WebSocket with auto-reconnect |
| State | **Zustand** | Minimal, no boilerplate |

---

## 3. System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        LINUX SERVER                             │
│                                                                 │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │ Log      │───▶│ Detection    │───▶│ Response Engine       │   │
│  │ Collector│    │ Engine       │    │ (block/rate-limit/    │   │
│  │          │    │ (rules+ML+   │    │  alert)               │   │
│  │ - auth   │    │  anomaly)    │    └──────────┬───────────┘   │
│  │ - nginx  │    └──────┬───────┘               │               │
│  │ - apache │           │                       │               │
│  │ - syslog │    ┌──────▼───────┐    ┌──────────▼───────────┐   │
│  │ - app    │    │ Threat Store │    │ Firewall Adapter     │   │
│  │ - kernel │    │ (SQLite)     │    │ (iptables/nft/ufw)   │   │
│  └──────────┘    └──────┬───────┘    └──────────────────────┘   │
│                         │                                       │
│  ┌──────────────────────▼───────────────────────────────────┐   │
│  │                    sentinelctl CLI                        │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                         │                                       │
│  ┌──────────────────────▼───────────────────────────────────┐   │
│  │              Notification Bus                             │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐  │   │
│  │  │ Telegram │ │ Webhook  │ │ WhatsApp │ │ Email      │  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                         │ (opt-in)                              │
└─────────────────────────┼──────────────────────────────────────┘
                          │ TLS + Agent Token
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CLOUD SaaS (Optional)                        │
│                                                                 │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────────────────┐ │
│  │ FastAPI    │  │ PostgreSQL   │  │ Next.js Dashboard       │ │
│  │ Backend    │──│ + Redis      │──│ (React, WebSocket)      │ │
│  │            │  │              │  │                         │ │
│  └────────────┘  └──────────────┘  └─────────────────────────┘ │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Global Threat Intelligence (aggregated, anonymized)      │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Log Collector** watches files via inotify, tails new lines
2. Each line passes through **Parser** (format-specific: syslog, CLF, JSON)
3. Parsed events enter the **Detection Pipeline** (sequential):
   - Stage 1: **Rule Engine** (regex patterns, known signatures) — instant
   - Stage 2: **Anomaly Detector** (statistical baselines) — <10ms
   - Stage 3: **LLM Classifier** (optional, for ambiguous events) — async
4. Events scoring above threshold enter **Response Engine**
5. Response Engine executes actions based on severity policy
6. All events + actions written to **Threat Store** (SQLite)
7. **Notification Bus** dispatches alerts to configured channels
8. **Cloud Sync** (if enabled) sends threat summaries (never raw logs by default)

---

## 4. Repository Structure

```
sentinel-ai/
├── agent/                          # Core agent (systemd service)
│   ├── sentinel/
│   │   ├── __init__.py
│   │   ├── main.py                 # Entry point, service lifecycle
│   │   ├── collector/
│   │   │   ├── __init__.py
│   │   │   ├── watcher.py          # inotify file watcher
│   │   │   ├── tailer.py           # Log line tailer with offset tracking
│   │   │   └── discovery.py        # Auto-discover log files on system
│   │   ├── parser/
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Abstract parser interface
│   │   │   ├── syslog.py           # auth.log, syslog format
│   │   │   ├── nginx.py            # Nginx access/error logs
│   │   │   ├── apache.py           # Apache combined/common log
│   │   │   ├── json_log.py         # Structured JSON logs
│   │   │   └── kernel.py           # dmesg / kernel ring buffer
│   │   ├── detector/
│   │   │   ├── __init__.py
│   │   │   ├── pipeline.py         # Orchestrates detection stages
│   │   │   ├── rules/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── engine.py       # Rule matching engine
│   │   │   │   ├── ssh.py          # SSH brute-force rules
│   │   │   │   ├── web.py          # Web attack rules (SQLi, XSS, path traversal)
│   │   │   │   ├── dos.py          # Rate/flood detection rules
│   │   │   │   └── system.py       # Privilege escalation, suspicious commands
│   │   │   ├── anomaly/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── baseline.py     # Statistical baseline builder
│   │   │   │   ├── detector.py     # Anomaly scoring
│   │   │   │   └── models.py       # Isolation forest, z-score models
│   │   │   └── llm/
│   │   │       ├── __init__.py
│   │   │       ├── classifier.py   # LLM-based threat classification
│   │   │       └── providers.py    # Ollama, OpenAI, Anthropic adapters
│   │   ├── responder/
│   │   │   ├── __init__.py
│   │   │   ├── engine.py           # Response decision engine
│   │   │   ├── firewall/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── base.py         # Abstract firewall interface
│   │   │   │   ├── iptables.py
│   │   │   │   ├── nftables.py
│   │   │   │   └── ufw.py
│   │   │   ├── actions.py          # Block, rate-limit, ban, whitelist
│   │   │   └── policy.py           # Severity → action mapping
│   │   ├── store/
│   │   │   ├── __init__.py
│   │   │   ├── database.py         # SQLite connection + migrations
│   │   │   ├── models.py           # SQLAlchemy/dataclass models
│   │   │   └── queries.py          # Common query patterns
│   │   ├── notifier/
│   │   │   ├── __init__.py
│   │   │   ├── bus.py              # Notification dispatcher
│   │   │   ├── telegram.py
│   │   │   ├── webhook.py
│   │   │   ├── whatsapp.py
│   │   │   └── email.py
│   │   ├── cloud/
│   │   │   ├── __init__.py
│   │   │   ├── sync.py             # Cloud heartbeat + threat sync
│   │   │   └── auth.py             # Agent token management
│   │   ├── config/
│   │   │   ├── __init__.py
│   │   │   ├── loader.py           # YAML config loader
│   │   │   ├── schema.py           # Config validation (pydantic)
│   │   │   └── defaults.py         # Default config values
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── logging.py          # Structured logging setup
│   │       ├── geo.py              # IP geolocation (offline MaxMind DB)
│   │       └── system.py           # OS detection, privilege checks
│   ├── tests/
│   │   ├── conftest.py
│   │   ├── test_collector/
│   │   ├── test_parser/
│   │   ├── test_detector/
│   │   ├── test_responder/
│   │   └── test_notifier/
│   ├── pyproject.toml
│   └── sentinel.service            # systemd unit file
│
├── cli/                            # CLI tool (sentinelctl)
│   ├── sentinel_cli/
│   │   ├── __init__.py
│   │   ├── main.py                 # Click group entry point
│   │   ├── commands/
│   │   │   ├── __init__.py
│   │   │   ├── install.py          # sentinelctl install
│   │   │   ├── status.py           # sentinelctl status
│   │   │   ├── scan.py             # sentinelctl scan [--deep]
│   │   │   ├── threats.py          # sentinelctl threats
│   │   │   ├── logs.py             # sentinelctl logs
│   │   │   ├── block.py            # sentinelctl block/unblock
│   │   │   ├── ai.py               # sentinelctl ai explain <id>
│   │   │   └── config.py           # sentinelctl config edit/show/set
│   │   ├── output.py               # Rich table/JSON output formatting
│   │   └── client.py               # Unix socket client to agent daemon
│   ├── tests/
│   ├── pyproject.toml
│   └── README.md
│
├── ai/                             # AI models and training
│   ├── models/
│   │   ├── rules/                  # YAML rule definitions
│   │   │   ├── ssh_bruteforce.yml
│   │   │   ├── web_sqli.yml
│   │   │   ├── web_xss.yml
│   │   │   ├── web_traversal.yml
│   │   │   ├── dos_flood.yml
│   │   │   └── priv_escalation.yml
│   │   └── anomaly/
│   │       └── pretrained/         # Baseline models (serialized)
│   ├── training/
│   │   ├── generate_dataset.py     # Synthetic training data
│   │   ├── train_anomaly.py        # Train anomaly detector
│   │   └── evaluate.py             # Model evaluation
│   └── prompts/
│       ├── classify_threat.txt     # LLM prompt: classify log event
│       └── explain_threat.txt      # LLM prompt: explain threat to user
│
├── bots/                           # Messaging bot integrations
│   ├── sentinel_bot/
│   │   ├── __init__.py
│   │   ├── telegram/
│   │   │   ├── __init__.py
│   │   │   ├── bot.py              # python-telegram-bot handler
│   │   │   ├── commands.py         # /status, /threats, /block
│   │   │   └── auth.py             # Chat ID verification
│   │   ├── webhook/
│   │   │   ├── __init__.py
│   │   │   └── sender.py           # Generic webhook POST
│   │   └── whatsapp/
│   │       ├── __init__.py
│   │       └── bot.py              # WhatsApp Business API
│   ├── tests/
│   └── pyproject.toml
│
├── cloud/                          # Cloud SaaS backend
│   ├── sentinel_cloud/
│   │   ├── __init__.py
│   │   ├── app.py                  # FastAPI application
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── agents.py           # Agent registration + heartbeat
│   │   │   ├── threats.py          # Threat aggregation endpoints
│   │   │   ├── users.py            # User management
│   │   │   └── webhooks.py         # Incoming webhook handlers
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── agent.py
│   │   │   ├── threat.py
│   │   │   ├── user.py
│   │   │   └── organization.py
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── intelligence.py     # Global threat intelligence
│   │   │   ├── aggregator.py       # Multi-server threat aggregation
│   │   │   └── alerting.py         # Cloud-side alerting
│   │   ├── ws/
│   │   │   └── realtime.py         # WebSocket handlers
│   │   └── db/
│   │       ├── __init__.py
│   │       ├── postgres.py         # SQLAlchemy async + PostgreSQL
│   │       └── migrations/         # Alembic migrations
│   ├── tests/
│   ├── pyproject.toml
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── dashboard/                      # Next.js web dashboard
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx
│   │   │   ├── page.tsx            # Overview
│   │   │   ├── threats/
│   │   │   ├── servers/
│   │   │   ├── logs/
│   │   │   ├── ai-insights/
│   │   │   └── settings/
│   │   ├── components/
│   │   │   ├── ui/                 # shadcn components
│   │   │   ├── threat-table.tsx
│   │   │   ├── severity-badge.tsx
│   │   │   ├── server-card.tsx
│   │   │   ├── attack-map.tsx
│   │   │   └── real-time-feed.tsx
│   │   ├── lib/
│   │   │   ├── api.ts              # API client
│   │   │   ├── ws.ts               # WebSocket client
│   │   │   └── store.ts            # Zustand stores
│   │   └── types/
│   │       └── index.ts
│   ├── package.json
│   ├── tailwind.config.ts
│   ├── next.config.js
│   └── Dockerfile
│
├── docs/
│   ├── architecture.md
│   ├── installation.md
│   ├── configuration.md
│   ├── rules-authoring.md
│   ├── api-reference.md
│   ├── bot-setup.md
│   └── contributing.md
│
├── install.sh                      # One-line installer
├── LICENSE
├── README.md
├── CLAUDE.md
├── Makefile                        # Top-level dev commands
└── docker-compose.dev.yml          # Full dev stack
```

---

## 5. Agent Core Design

### 5.1 Service Lifecycle

```python
# agent/sentinel/main.py — Simplified lifecycle

class SentinelAgent:
    def __init__(self, config_path="/etc/sentinel/config.yml"):
        self.config = ConfigLoader(config_path).load()
        self.store = ThreatStore(self.config.database.path)
        self.collector = LogCollector(self.config.logs)
        self.detector = DetectionPipeline(self.config.detection)
        self.responder = ResponseEngine(self.config.response)
        self.notifier = NotificationBus(self.config.notifications)
        self.cloud = CloudSync(self.config.cloud) if self.config.cloud.enabled else None
        self.socket = UnixSocketServer("/var/run/sentinel/sentinel.sock")

    async def run(self):
        """Main event loop."""
        await self.store.initialize()
        await self.collector.discover_logs()  # Auto-detect log sources

        async for event in self.collector.stream():
            threat = await self.detector.analyze(event)
            if threat:
                await self.store.save_threat(threat)
                action = await self.responder.decide(threat)
                if action:
                    await self.responder.execute(action)
                    await self.store.save_action(action)
                await self.notifier.dispatch(threat, action)
                if self.cloud:
                    await self.cloud.push_threat(threat)
```

### 5.2 Log Discovery Engine

On first run (`sentinelctl install`), the agent auto-discovers logs:

```python
# Discovery priority order:
DISCOVERY_MAP = {
    "ssh": [
        "/var/log/auth.log",           # Debian/Ubuntu
        "/var/log/secure",             # RHEL/CentOS
    ],
    "nginx": [
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/nginx/*/access.log",  # Virtual hosts
    ],
    "apache": [
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
        "/var/log/apache2/*/access.log",
    ],
    "system": [
        "/var/log/syslog",
        "/var/log/messages",
    ],
    "kernel": [
        "/var/log/kern.log",
    ],
    "firewall": [
        "/var/log/ufw.log",
    ],
}

# Discovery also reads:
# - systemctl list-units → find active web servers
# - nginx -T / apache2ctl -S → find configured log paths
# - journalctl --list-boots → check systemd journal availability
```

### 5.3 Inter-Process Communication

The agent daemon exposes a **Unix domain socket** for the CLI:

```
/var/run/sentinel/sentinel.sock
```

Protocol: JSON-RPC 2.0 over Unix socket

```json
// Request
{"jsonrpc": "2.0", "method": "threats.list", "params": {"severity": "HIGH", "limit": 20}, "id": 1}

// Response
{"jsonrpc": "2.0", "result": {"threats": [...], "total": 42}, "id": 1}
```

Available methods:
- `agent.status` — Health check, uptime, stats
- `threats.list` — Query threats with filters
- `threats.get` — Single threat detail
- `threats.explain` — AI explanation for threat
- `logs.tail` — Stream recent log events
- `firewall.block` — Block an IP
- `firewall.unblock` — Unblock an IP
- `firewall.list` — List blocked IPs
- `scan.start` — Trigger deep scan
- `config.get` / `config.set` — Runtime config

---

## 6. AI Detection Engine

### 6.1 Three-Stage Pipeline

```
Log Event
    │
    ▼
┌──────────────────────────────────┐
│ Stage 1: Rule Engine             │  Latency: <1ms
│ - Pattern matching (regex)       │  Confidence: HIGH for known attacks
│ - Known attack signatures        │  Coverage: Known threats only
│ - IP reputation (local list)     │
│ → Produces: match/no-match +     │
│   rule_id + severity             │
└──────────────┬───────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│ Stage 2: Anomaly Detector        │  Latency: <10ms
│ - Request rate deviation         │  Confidence: MEDIUM
│ - Unusual access patterns        │  Coverage: Unknown/novel threats
│ - Geographic anomalies           │
│ - Time-based anomalies           │
│ → Produces: anomaly_score (0-1)  │
└──────────────┬───────────────────┘
               │ (if ambiguous: score 0.4-0.7)
               ▼
┌──────────────────────────────────┐
│ Stage 3: LLM Classifier          │  Latency: 200ms-2s
│ (Optional, async)                │  Confidence: Contextual
│ - Contextual analysis            │  Coverage: Everything
│ - Natural language explanation   │
│ → Produces: classification +     │
│   explanation + confidence       │
└──────────────────────────────────┘
```

### 6.2 Rule Definition Format

Rules are defined in YAML for easy authoring and community contributions:

```yaml
# ai/models/rules/ssh_bruteforce.yml
id: SSH_BRUTE_001
name: SSH Brute Force Attack
description: Multiple failed SSH login attempts from same IP
severity: HIGH
log_source: ssh

conditions:
  - field: message
    pattern: "Failed password for .+ from (?P<attacker_ip>[\\d.]+)"
  - field: message
    pattern: "Invalid user .+ from (?P<attacker_ip>[\\d.]+)"

aggregation:
  group_by: attacker_ip
  window: 300        # 5 minutes
  threshold: 5       # 5 failures triggers

actions:
  - block_ip:
      duration: 3600   # 1 hour
  - notify:
      level: HIGH

tags: [ssh, brute-force, authentication]
```

### 6.3 Anomaly Detection

```python
# Behavioral baselines tracked per source:

class BaselineMetrics:
    requests_per_minute: float      # Normal rate
    unique_ips_per_hour: float      # Normal diversity
    error_rate: float               # Normal error ratio (4xx, 5xx)
    geo_distribution: dict          # Normal country distribution
    hour_distribution: list[float]  # Normal hourly pattern (24 buckets)
    path_entropy: float             # Normal URL diversity

# Anomaly score = weighted combination of:
# - Rate deviation (z-score from baseline)
# - Geographic novelty (new country accessing sensitive endpoints)
# - Temporal novelty (requests at unusual hours)
# - Pattern novelty (unusual URL patterns, missing headers)
```

### 6.4 Threat Scoring

Every event gets a unified risk score:

```
risk_score = (
    rule_weight * rule_score +          # 0.5 * (0 or 1)
    anomaly_weight * anomaly_score +    # 0.3 * (0.0 - 1.0)
    llm_weight * llm_score              # 0.2 * (0.0 - 1.0)
)

# Mapped to severity:
# 0.0 - 0.2  → INFO
# 0.2 - 0.4  → LOW
# 0.4 - 0.6  → MEDIUM
# 0.6 - 0.8  → HIGH
# 0.8 - 1.0  → CRITICAL
```

---

## 7. CLI Interface

### 7.1 Command Reference

```bash
# Installation & Setup
sentinelctl install                    # Interactive setup wizard
sentinelctl uninstall                  # Clean removal
sentinelctl upgrade                    # Upgrade to latest version

# Service Management
sentinelctl start                      # Start agent daemon
sentinelctl stop                       # Stop agent daemon
sentinelctl restart                    # Restart agent
sentinelctl status                     # Agent health + summary stats

# Threat Monitoring
sentinelctl threats                    # List recent threats (table format)
sentinelctl threats --severity HIGH    # Filter by severity
sentinelctl threats --since 1h         # Time filter
sentinelctl threats --format json      # JSON output for scripting
sentinelctl threats --watch            # Live stream

# Log Operations
sentinelctl logs                       # Show monitored log sources
sentinelctl logs tail                  # Live parsed log stream
sentinelctl logs discover              # Re-discover log sources

# Scanning
sentinelctl scan                       # Quick security scan
sentinelctl scan --deep                # Full system audit
sentinelctl scan --report              # Generate PDF/HTML report

# IP Management
sentinelctl block <ip>                 # Block IP immediately
sentinelctl block <ip> --duration 24h  # Temporary block
sentinelctl unblock <ip>               # Remove block
sentinelctl blocklist                  # Show all blocked IPs
sentinelctl whitelist add <ip>         # Whitelist an IP
sentinelctl whitelist remove <ip>

# AI Features
sentinelctl ai explain <threat_id>     # AI explanation of threat
sentinelctl ai analyze <log_file>      # Analyze specific log file
sentinelctl ai summary                 # Daily threat summary

# Configuration
sentinelctl config show                # Display current config
sentinelctl config edit                # Open config in $EDITOR
sentinelctl config set <key> <value>   # Set config value
sentinelctl config validate            # Validate config file

# Cloud (Optional)
sentinelctl cloud connect <token>      # Connect to SaaS
sentinelctl cloud disconnect           # Disconnect from SaaS
sentinelctl cloud status               # Cloud connection status

# Bot Setup
sentinelctl bot telegram setup         # Interactive Telegram setup
sentinelctl bot webhook add <url>      # Add webhook endpoint
sentinelctl bot test                   # Send test notification
```

### 7.2 Output Design

```
$ sentinelctl status

  Sentinel AI Agent v1.0.0
  Status:     ● Running (pid 12847)
  Uptime:     3d 14h 22m
  CPU/Mem:    1.2% / 38 MB

  Monitoring:
    /var/log/auth.log        ● active    last: 2s ago
    /var/log/nginx/access    ● active    last: <1s ago
    /var/log/syslog          ● active    last: 5s ago

  Last 24h:
    Events processed:  142,847
    Threats detected:  23
    IPs blocked:       7
    Critical alerts:   1

$ sentinelctl threats

  ID       Time              Source   Severity   Type                Attacker IP
  ──────── ───────────────── ──────── ────────── ─────────────────── ───────────────
  THR-0142 2026-02-09 14:23  ssh      CRITICAL   Brute Force         203.0.113.42
  THR-0141 2026-02-09 14:20  nginx    HIGH       SQL Injection       198.51.100.17
  THR-0140 2026-02-09 14:18  nginx    HIGH       Path Traversal      198.51.100.17
  THR-0139 2026-02-09 13:45  ssh      MEDIUM     Failed Auth (3x)    192.0.2.88
  THR-0138 2026-02-09 13:30  nginx    LOW        Scanner Detected    203.0.113.55
```

---

## 8. Database Schemas

### 8.1 Local SQLite Schema

```sql
-- Threat events
CREATE TABLE threats (
    id              TEXT PRIMARY KEY,     -- THR-{ULID}
    created_at      TEXT NOT NULL,        -- ISO 8601
    source          TEXT NOT NULL,        -- ssh, nginx, apache, system
    severity        TEXT NOT NULL,        -- INFO, LOW, MEDIUM, HIGH, CRITICAL
    type            TEXT NOT NULL,        -- brute_force, sqli, xss, dos, etc.
    attacker_ip     TEXT,
    attacker_geo    TEXT,                 -- Country code
    description     TEXT NOT NULL,
    raw_log         TEXT,                 -- Original log line(s)
    risk_score      REAL NOT NULL,        -- 0.0 - 1.0
    rule_id         TEXT,                 -- Rule that matched (if any)
    anomaly_score   REAL,                 -- Anomaly detector score
    llm_explanation TEXT,                 -- LLM analysis (if available)
    status          TEXT DEFAULT 'open',  -- open, acknowledged, resolved, false_positive
    resolved_at     TEXT,
    resolved_by     TEXT
);

CREATE INDEX idx_threats_created ON threats(created_at DESC);
CREATE INDEX idx_threats_severity ON threats(severity);
CREATE INDEX idx_threats_ip ON threats(attacker_ip);
CREATE INDEX idx_threats_status ON threats(status);

-- Response actions taken
CREATE TABLE actions (
    id              TEXT PRIMARY KEY,     -- ACT-{ULID}
    threat_id       TEXT NOT NULL REFERENCES threats(id),
    created_at      TEXT NOT NULL,
    type            TEXT NOT NULL,        -- block, rate_limit, ban, alert
    target_ip       TEXT,
    duration        INTEGER,             -- Seconds (NULL = permanent)
    expires_at      TEXT,
    status          TEXT DEFAULT 'active', -- active, expired, revoked
    revoked_by      TEXT,
    revoked_at      TEXT
);

CREATE INDEX idx_actions_threat ON actions(threat_id);
CREATE INDEX idx_actions_expires ON actions(expires_at);
CREATE INDEX idx_actions_status ON actions(status);

-- Monitored log sources
CREATE TABLE log_sources (
    id              TEXT PRIMARY KEY,
    path            TEXT NOT NULL UNIQUE,
    type            TEXT NOT NULL,        -- ssh, nginx, apache, syslog, kernel
    status          TEXT DEFAULT 'active',
    last_offset     INTEGER DEFAULT 0,   -- File read offset for resume
    last_inode      INTEGER,             -- Detect log rotation
    discovered_at   TEXT NOT NULL,
    last_event_at   TEXT
);

-- Behavioral baselines (per source, per hour)
CREATE TABLE baselines (
    source_type     TEXT NOT NULL,
    hour_of_day     INTEGER NOT NULL,    -- 0-23
    day_of_week     INTEGER NOT NULL,    -- 0-6
    metric          TEXT NOT NULL,        -- requests_per_min, error_rate, etc.
    mean            REAL NOT NULL,
    stddev          REAL NOT NULL,
    sample_count    INTEGER NOT NULL,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (source_type, hour_of_day, day_of_week, metric)
);

-- IP reputation cache
CREATE TABLE ip_reputation (
    ip              TEXT PRIMARY KEY,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    total_events    INTEGER DEFAULT 0,
    threat_count    INTEGER DEFAULT 0,
    is_blocked      INTEGER DEFAULT 0,
    is_whitelisted  INTEGER DEFAULT 0,
    geo_country     TEXT,
    geo_city        TEXT,
    notes           TEXT
);

-- Notification log
CREATE TABLE notifications (
    id              TEXT PRIMARY KEY,
    threat_id       TEXT REFERENCES threats(id),
    channel         TEXT NOT NULL,        -- telegram, webhook, email
    sent_at         TEXT NOT NULL,
    status          TEXT NOT NULL,        -- sent, failed, pending
    error           TEXT
);

-- Agent config & state
CREATE TABLE agent_state (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
```

### 8.2 Cloud PostgreSQL Schema (additions to above)

```sql
-- Multi-tenant organizations
CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    plan            TEXT DEFAULT 'free',  -- free, pro, enterprise
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Users
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role            TEXT DEFAULT 'member', -- owner, admin, member, viewer
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Registered agents
CREATE TABLE agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    hostname        TEXT NOT NULL,
    ip_address      TEXT,
    os_info         TEXT,
    agent_version   TEXT,
    token_hash      TEXT UNIQUE NOT NULL,
    last_heartbeat  TIMESTAMPTZ,
    status          TEXT DEFAULT 'online',  -- online, offline, degraded
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Global threat intelligence (aggregated from all agents)
CREATE TABLE global_threats (
    ip              TEXT NOT NULL,
    threat_type     TEXT NOT NULL,
    report_count    INTEGER DEFAULT 1,
    first_reported  TIMESTAMPTZ DEFAULT now(),
    last_reported   TIMESTAMPTZ DEFAULT now(),
    confidence      REAL,
    PRIMARY KEY (ip, threat_type)
);
```

---

## 9. API Contracts

### 9.1 Cloud REST API

Base URL: `https://api.sentinel-ai.dev/v1`

#### Agent Endpoints (Agent → Cloud)

```
POST   /agents/register
       Body: { hostname, os_info, agent_version }
       Auth: Organization API key
       Response: { agent_id, token }

POST   /agents/{id}/heartbeat
       Body: { uptime, stats: { events_24h, threats_24h, blocked_ips } }
       Auth: Agent token
       Response: { ok: true, commands: [...] }

POST   /agents/{id}/threats
       Body: { threats: [{ id, severity, type, attacker_ip, description, risk_score, created_at }] }
       Auth: Agent token
       Response: { received: true, intelligence: { known_bad_ips: [...] } }
```

#### Dashboard Endpoints (Dashboard → Cloud)

```
GET    /threats
       Query: ?severity=HIGH&since=2026-02-09&agent_id=xxx&page=1&limit=50
       Auth: Bearer JWT
       Response: { threats: [...], total, page, pages }

GET    /threats/{id}
       Auth: Bearer JWT
       Response: { threat, actions, timeline, ai_explanation }

GET    /agents
       Auth: Bearer JWT
       Response: { agents: [{ id, hostname, status, stats }] }

GET    /agents/{id}
       Auth: Bearer JWT
       Response: { agent, recent_threats, health_history }

GET    /dashboard/overview
       Auth: Bearer JWT
       Response: { total_agents, online, threats_24h, severity_breakdown, top_attackers, timeline }

POST   /agents/{id}/command
       Body: { action: "block_ip", params: { ip: "1.2.3.4", duration: 3600 } }
       Auth: Bearer JWT (admin+)
       Response: { command_id, status: "queued" }

GET    /intelligence/ip/{ip}
       Auth: Bearer JWT
       Response: { reports, threat_types, confidence, first_seen, last_seen }
```

#### Auth Endpoints

```
POST   /auth/login
       Body: { email, password }
       Response: { access_token, refresh_token, user }

POST   /auth/refresh
       Body: { refresh_token }
       Response: { access_token }

POST   /auth/api-keys
       Auth: Bearer JWT (admin+)
       Body: { name, permissions }
       Response: { api_key }
```

### 9.2 WebSocket Events (Cloud → Dashboard)

```
Connection: wss://api.sentinel-ai.dev/ws?token={jwt}

// Server → Client events:
{ event: "threat.new",        data: { threat } }
{ event: "threat.updated",    data: { threat_id, changes } }
{ event: "agent.status",      data: { agent_id, status } }
{ event: "action.executed",   data: { action } }
{ event: "stats.update",      data: { overview_stats } }
```

---

## 10. Bot Integrations

### 10.1 Telegram Bot

```
Bot Commands:
  /start              — Register and authenticate
  /status             — Agent status summary
  /threats            — Recent threats (last 1h)
  /threats high       — High+ severity only
  /block 1.2.3.4      — Block IP (requires admin)
  /unblock 1.2.3.4    — Unblock IP (requires admin)
  /report             — Generate daily report
  /mute 1h            — Mute non-critical alerts
  /help               — Command reference

Alert Message Format:
  🔴 CRITICAL THREAT DETECTED
  ─────────────────────────
  Type:     SSH Brute Force
  Source:   auth.log
  Attacker: 203.0.113.42 (CN)
  Score:    0.92
  Time:     2026-02-09 14:23 UTC

  Action:   ✅ IP Blocked (1h)

  [View Details] [Unblock] [Mark Safe]

Permission Levels:
  viewer  — Can view status + threats
  admin   — Can block/unblock IPs
  owner   — Can configure bot settings
```

### 10.2 Webhook Format

```json
POST {webhook_url}
Content-Type: application/json
X-Sentinel-Signature: sha256={hmac}

{
  "event": "threat.detected",
  "timestamp": "2026-02-09T14:23:00Z",
  "agent": {
    "id": "agent_01",
    "hostname": "web-prod-01"
  },
  "threat": {
    "id": "THR-0142",
    "severity": "CRITICAL",
    "type": "brute_force",
    "attacker_ip": "203.0.113.42",
    "description": "SSH brute force: 47 failed attempts in 5 minutes",
    "risk_score": 0.92
  },
  "action": {
    "type": "block",
    "duration": 3600
  }
}
```

---

## 11. Cloud SaaS Platform

### 11.1 Multi-Tenancy

```
Organization (tenant)
  ├── Users (RBAC: owner, admin, member, viewer)
  ├── Agents (connected servers)
  ├── API Keys
  └── Settings (alerting, integrations)
```

### 11.2 Cloud Agent Communication

```
Agent ──[ heartbeat every 60s ]──▶ Cloud
       ──[ threat batch push ]───▶ Cloud
       ◀──[ commands queue ]────── Cloud

Heartbeat payload: { uptime, cpu, mem, events_1h, threats_1h }
Threat push: Summaries only (no raw logs unless opted in)
Commands: block/unblock/scan/update-rules
```

### 11.3 Global Threat Intelligence

- Anonymized threat data aggregated across all connected agents
- IP reputation scores from community reports
- Shared attack pattern signatures
- New rule distribution to agents
- Opt-in only, agents can disable

---

## 12. Web Dashboard

### 12.1 Pages

| Page | Purpose |
|------|---------|
| **Overview** | Total agents, threats (24h), severity breakdown chart, attack timeline, top attackers |
| **Threats** | Sortable/filterable table, detail drawer with AI explanation, bulk actions |
| **Servers** | Agent list with health status, click into per-server view |
| **Logs** | Summarized log stream (not raw), filterable by source/severity |
| **AI Insights** | Trend analysis, predicted threats, attack pattern explanations |
| **Settings** | Notifications, integrations, team management, API keys |

### 12.2 Real-Time

- WebSocket connection for live threat feed
- Toast notifications for HIGH/CRITICAL
- Auto-refresh stats every 10s
- Sound alerts (configurable)

---

## 13. Configuration System

### 13.1 Main Config File

Location: `/etc/sentinel/config.yml`

```yaml
# /etc/sentinel/config.yml

agent:
  id: auto                          # Auto-generated on install
  hostname: auto                    # Detected from system
  log_level: info                   # debug, info, warning, error

# Log sources — "auto" discovers automatically
logs:
  discovery: true                   # Auto-discover on startup
  sources:
    - path: /var/log/auth.log
      type: ssh
    - path: /var/log/nginx/access.log
      type: nginx
    # Additional sources added by discovery

# Detection settings
detection:
  rules:
    enabled: true
    custom_rules_dir: /etc/sentinel/rules.d/

  anomaly:
    enabled: true
    learning_period: 7d             # Days before anomaly detection activates
    sensitivity: medium             # low, medium, high

  llm:
    enabled: false                  # Opt-in
    provider: ollama                # ollama, openai, anthropic
    model: llama3                   # Model name
    endpoint: http://localhost:11434
    # api_key: sk-...              # For cloud LLM providers

# Response policy
response:
  auto_block: true                  # Auto-block on HIGH/CRITICAL
  block_duration:
    HIGH: 3600                      # 1 hour
    CRITICAL: 86400                 # 24 hours
  max_blocks: 1000                  # Safety limit
  whitelist:
    - 127.0.0.1
    - 10.0.0.0/8
    - 192.168.0.0/16

  firewall:
    backend: auto                   # auto, iptables, nftables, ufw

# Notifications
notifications:
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""
    min_severity: HIGH              # Only alert on HIGH+

  webhook:
    enabled: false
    url: ""
    secret: ""                      # For HMAC signature
    min_severity: MEDIUM

  email:
    enabled: false
    smtp_host: ""
    smtp_port: 587
    from: ""
    to: []
    min_severity: CRITICAL

# Cloud connection (optional)
cloud:
  enabled: false
  endpoint: https://api.sentinel-ai.dev
  token: ""
  sync_interval: 60                 # Seconds
  send_raw_logs: false              # Privacy: never by default

# Database
database:
  path: /var/lib/sentinel/sentinel.db
  retention_days: 90                # Auto-purge old data

# Performance
performance:
  max_events_per_second: 10000
  batch_size: 100
  worker_threads: 2
```

---

## 14. Installation & Packaging

### 14.1 One-Line Installer

```bash
curl -fsSL https://get.sentinel-ai.dev | sudo bash
```

The `install.sh` script:

1. Detects OS (Ubuntu/Debian/CentOS/RHEL)
2. Installs Python 3.11+ if needed
3. Creates `/etc/sentinel/`, `/var/lib/sentinel/`, `/var/log/sentinel/`
4. Installs agent + CLI via pip (in venv at `/opt/sentinel/`)
5. Creates `sentinel` system user
6. Installs systemd service
7. Runs `sentinelctl install` (interactive discovery)
8. Starts the service

### 14.2 systemd Service

```ini
# /etc/systemd/system/sentinel-agent.service

[Unit]
Description=Sentinel AI Security Agent
After=network.target
Documentation=https://github.com/sentinel-ai/sentinel-ai

[Service]
Type=notify
User=root
Group=sentinel
ExecStart=/opt/sentinel/venv/bin/python -m sentinel.main
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
WatchdogSec=30
StandardOutput=journal
StandardError=journal
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/sentinel /var/log/sentinel /var/run/sentinel /etc/sentinel

[Install]
WantedBy=multi-user.target
```

### 14.3 Package Formats

| Format | Target |
|--------|--------|
| **pip** | `pip install sentinel-ai` |
| **deb** | Ubuntu/Debian apt repository |
| **rpm** | CentOS/RHEL yum repository |
| **Docker** | `docker run sentinel-ai/agent` (for cloud/testing) |
| **install.sh** | Universal single-script installer |

---

## 15. Security Model

### 15.1 Agent Security

- Agent runs as **root** (required for firewall and log access) but drops privileges where possible
- Unix socket permissions: `0660`, group `sentinel`
- Config file permissions: `0640`, owner `root:sentinel`
- Database file permissions: `0640`
- No open network ports (Unix socket only, unless cloud sync enabled)
- Agent token stored with `0600` permissions

### 15.2 Cloud Security

- All cloud communication over TLS 1.3
- Agent authentication via HMAC-signed tokens (rotatable)
- JWT tokens with short expiry (15min) + refresh tokens
- API rate limiting per organization
- No raw log transmission by default
- Webhook payloads signed with HMAC-SHA256

### 15.3 Fail-Safe Behaviors

- If AI is uncertain (score 0.4-0.6), **alert only** — never auto-block
- Maximum block list size (configurable, default 1000)
- Whitelist always takes precedence over auto-block
- Blocked IPs have expiry by default (never permanent unless explicitly set)
- Agent crash → systemd auto-restart within 5 seconds
- Database corruption → agent recreates from scratch, logs warning

---

## 16. Implementation Phases

### Phase 1: Foundation (Weeks 1-3)

**Goal**: Working agent that monitors SSH logs and blocks brute-force attacks

- [ ] Project scaffolding (repo, pyproject.toml, Makefile, CI)
- [ ] Config system (YAML loader, validation, defaults)
- [ ] Log collector (file watcher, tailer, offset tracking)
- [ ] SSH log parser
- [ ] Rule engine with SSH brute-force rules
- [ ] SQLite threat store (schema, basic queries)
- [ ] Firewall adapter (iptables + ufw)
- [ ] Response engine (block/unblock)
- [ ] Basic CLI (install, status, threats, block/unblock)
- [ ] systemd service file
- [ ] install.sh (basic version)
- [ ] Unit tests for all components

**Deliverable**: `sentinelctl` that detects and blocks SSH brute-force attacks

### Phase 2: Web Monitoring + Detection (Weeks 4-6)

**Goal**: Full log coverage with anomaly detection

- [ ] Nginx/Apache log parsers
- [ ] System log parser (syslog, kernel)
- [ ] Log auto-discovery engine
- [ ] Web attack rules (SQLi, XSS, path traversal, scanners)
- [ ] DDoS/flood detection rules
- [ ] Privilege escalation rules
- [ ] Anomaly detection (baseline builder, scoring)
- [ ] IP geolocation (offline MaxMind)
- [ ] IP reputation tracking
- [ ] CLI enhancements (scan, logs, filtering)
- [ ] Integration tests

**Deliverable**: Comprehensive threat detection across all major log sources

### Phase 3: AI + Notifications (Weeks 7-9)

**Goal**: LLM integration and alerting

- [ ] LLM classifier (Ollama adapter for local inference)
- [ ] OpenAI/Anthropic adapters (cloud LLM option)
- [ ] AI explanation generation
- [ ] `sentinelctl ai explain` command
- [ ] Notification bus architecture
- [ ] Telegram bot (full command set)
- [ ] Webhook integration
- [ ] Email notifications
- [ ] Severity-based notification routing
- [ ] Daily/weekly summary reports

**Deliverable**: AI-enhanced detection with real-time alerting

### Phase 4: Cloud SaaS (Weeks 10-14)

**Goal**: Multi-server cloud platform

- [ ] FastAPI backend (auth, agents, threats APIs)
- [ ] PostgreSQL schema + migrations
- [ ] Agent → Cloud sync protocol
- [ ] Cloud → Agent command channel
- [ ] JWT authentication system
- [ ] WebSocket real-time events
- [ ] Global threat intelligence aggregation
- [ ] Next.js dashboard (all 6 pages)
- [ ] Dark mode
- [ ] Docker Compose deployment
- [ ] Cloud API tests

**Deliverable**: Full SaaS platform with dashboard

### Phase 5: Hardening + Launch (Weeks 15-17)

**Goal**: Production-ready open-source release

- [ ] Security audit (dependencies, permissions, injection vectors)
- [ ] Performance testing (10k events/sec target)
- [ ] Log rotation handling
- [ ] Graceful degradation tests
- [ ] deb/rpm packages
- [ ] Documentation (all docs/ files)
- [ ] GitHub Actions CI/CD
- [ ] README with badges, screenshots, quickstart
- [ ] Contributing guide
- [ ] Release v1.0.0

**Deliverable**: Public GitHub release

---

## 17. Deployment Plan

### Local Agent Deployment

```bash
# Install
curl -fsSL https://get.sentinel-ai.dev | sudo bash

# Verify
sentinelctl status

# Configure
sentinelctl config edit

# Optional: Connect to cloud
sentinelctl cloud connect <org-token>

# Optional: Setup Telegram
sentinelctl bot telegram setup
```

### Cloud SaaS Deployment

```yaml
# docker-compose.prod.yml
services:
  api:
    image: sentinel-ai/cloud:latest
    environment:
      DATABASE_URL: postgresql://sentinel:pass@db:5432/sentinel
      REDIS_URL: redis://redis:6379
      JWT_SECRET: ${JWT_SECRET}
    ports:
      - "8000:8000"
    depends_on:
      - db
      - redis

  dashboard:
    image: sentinel-ai/dashboard:latest
    environment:
      NEXT_PUBLIC_API_URL: https://api.sentinel-ai.dev
    ports:
      - "3000:3000"

  db:
    image: postgres:16
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: sentinel
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD: ${DB_PASSWORD}

  redis:
    image: redis:7-alpine
    volumes:
      - redisdata:/data

  celery:
    image: sentinel-ai/cloud:latest
    command: celery -A sentinel_cloud.worker worker -l info
    depends_on:
      - redis
      - db

volumes:
  pgdata:
  redisdata:
```

### Recommended Infrastructure

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **Agent server** | Any Linux with Python 3.11+ | Same |
| **Cloud API** | 1 vCPU, 1GB RAM | 2 vCPU, 4GB RAM |
| **PostgreSQL** | 1 vCPU, 1GB RAM | 2 vCPU, 8GB RAM |
| **Redis** | 256MB RAM | 1GB RAM |
| **Dashboard** | Static hosting (Vercel/Cloudflare) | Same |

---

## Appendix: Makefile (Development Commands)

```makefile
.PHONY: install dev test lint format build

# Install all dependencies for development
install:
	cd agent && pip install -e ".[dev]"
	cd cli && pip install -e ".[dev]"
	cd bots && pip install -e ".[dev]"
	cd cloud && pip install -e ".[dev]"
	cd dashboard && npm install

# Run agent in development mode
dev-agent:
	cd agent && python -m sentinel.main --config dev.yml --log-level debug

# Run cloud API in development
dev-cloud:
	cd cloud && uvicorn sentinel_cloud.app:app --reload --port 8000

# Run dashboard in development
dev-dashboard:
	cd dashboard && npm run dev

# Run all tests
test:
	cd agent && pytest -v
	cd cli && pytest -v
	cd bots && pytest -v
	cd cloud && pytest -v
	cd dashboard && npm test

# Run single test file
test-one:
	cd agent && pytest -v $(FILE)

# Lint all Python code
lint:
	ruff check agent/ cli/ bots/ cloud/

# Format all Python code
format:
	ruff format agent/ cli/ bots/ cloud/

# Build packages
build:
	cd agent && python -m build
	cd cli && python -m build
	cd dashboard && npm run build
```

---

*This plan is a living document. Update as implementation progresses.*
