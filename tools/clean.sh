#!/bin/bash

# Sentinel Cleanup Tool
# Clears local agent state and optional database reset

set -e

echo "🧹 Sentinel Cleanup Tool"
echo "========================"

# 1. Stop Agent
echo "Stopping Sentinel services..."
npx sentinelctl stop || true

# 2. Clear Local State (~/.sentinel)
SENTINEL_DIR="$HOME/.sentinel"
if [ -d "$SENTINEL_DIR" ]; then
    echo "Found local state in $SENTINEL_DIR"
    ls -lh "$SENTINEL_DIR"
    
    read -p "🗑️  Clear local state (banned IPs, config Cache)? [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        rm -f "$SENTINEL_DIR/banned_ips.json"
        rm -f "$SENTINEL_DIR/*.lock"
        echo "✅ Local state cleared."
    fi
else
    echo "No local agent state found."
fi

# 3. Clear PM2 Logs
PM2_LOG_DIR="$HOME/.pm2/logs"
if [ -d "$PM2_LOG_DIR" ]; then
    echo "Found PM2 logs in $PM2_LOG_DIR"
    du -sh "$PM2_LOG_DIR"
    
    read -p "🗑️  Clear ALL PM2 logs? [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        pm2 flush
        rm -rf "$PM2_LOG_DIR/sentinel-agent*"
        echo "✅ Logs cleared."
    fi
fi

# 4. Check Database (Prisma)
DB_FILE="apps/web/prisma/dev.db" # Default SQLite path if local
if [ -f "$DB_FILE" ]; then
    echo "Found local SQLite database: $DB_FILE"
    ls -lh "$DB_FILE"
    
    read -p "⚠️  RESET DATABASE? This will delete all history/alerts! [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        rm "$DB_FILE"
        echo "✅ Database deleted. It will be recreated on next start."
        # Optional: Run prisma migrate
        # npx prisma migrate deploy
    fi
fi

echo "========================"
echo "✅ Cleanup complete."
echo "You can now run 'sentinelctl start'"
