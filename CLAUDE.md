# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

SentinelAI — an AI-powered, Linux-first server and website security platform. Open-source local agent with optional cloud SaaS dashboard. See `PROJECT_PLAN.md` for full architecture and implementation details.

## Architecture

- **agent/** — Core Python daemon (systemd service) that monitors logs, detects threats, blocks attackers
- **cli/** — `sentinelctl` CLI tool (Click-based), communicates with agent via Unix socket (JSON-RPC 2.0)
- **ai/** — Detection rules (YAML), anomaly models, LLM prompt templates
- **bots/** — Telegram, WhatsApp, webhook notification integrations
- **cloud/** — FastAPI backend for multi-server SaaS (PostgreSQL, Redis, Celery)
- **dashboard/** — Next.js 14 + shadcn/ui + Tailwind web frontend

## Tech Stack

- Agent/CLI/Bots/Cloud: Python 3.11+, pip packaging
- Local DB: SQLite; Cloud DB: PostgreSQL
- Dashboard: Next.js 14, TypeScript, shadcn/ui, Zustand, Recharts
- Firewall: iptables/nftables/ufw abstraction layer
- AI: scikit-learn (anomaly) + regex rules + optional LLM (Ollama/OpenAI/Anthropic)

## Key Design Decisions

- Agent works fully offline — cloud is opt-in only
- Detection pipeline: Rules (instant) → Anomaly (statistical) → LLM (async, optional)
- Never auto-block on ambiguous scores (0.4-0.6) — alert only
- Raw logs never sent to cloud unless user explicitly opts in
- Config at `/etc/sentinel/config.yml` (YAML), DB at `/var/lib/sentinel/sentinel.db`
- Agent ↔ CLI communication via Unix socket at `/var/run/sentinel/sentinel.sock`
