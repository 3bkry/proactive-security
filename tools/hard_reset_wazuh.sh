#!/bin/bash
set -e

# Color Constants
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

INSTALL_DIR="/opt/sentinel-agent"

echo -e "${RED}⚠️  Warning: This will DELETE all Wazuh data (logs, alerts, config) and start fresh.${NC}"
read -p "Are you sure? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo -e "${GREEN}🛑 Stopping Wazuh...${NC}"
cd "$INSTALL_DIR"

# Detect command again
if docker compose version &>/dev/null; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo "Docker Compose not found."
    exit 1
fi

$COMPOSE_CMD down -v

echo -e "${GREEN}🧹 Cleaning up artifacts...${NC}"
# Double check volumes are gone
docker volume prune -f

echo -e "${GREEN}� Refreshing configuration...${NC}"
cp docker-compose.wazuh.yml docker-compose.yml

echo -e "${GREEN}�🚀 Starting fresh...${NC}"
$COMPOSE_CMD up -d

echo -e "${GREEN}✔ Done. Please wait 2-3 minutes for initialization.${NC}"
