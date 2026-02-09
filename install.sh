#!/bin/bash
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}SentinelAI Installer${NC}"
echo "======================"

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "Node.js is not installed. Please install Node.js v18+."
    exit 1
fi

NODE_VERSION=$(node -v)
echo -e "${GREEN}Detected Node.js $NODE_VERSION${NC}"

# Check NPM
if ! command -v npm &> /dev/null; then
    echo "npm is not installed."
    exit 1
fi

echo "Installing dependencies..."
rm -rf node_modules package-lock.json apps/web/node_modules apps/web/package-lock.json
npm install
npm install
# Force install in web workspace to fix resolution issues
cd apps/web && npm install && cd ../../

echo "Building project..."
npm run build -w packages/core
npm run build -w apps/agent

echo -e "${GREEN}Installation complete!${NC}"

echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "To start the agent:"
echo "  npm start -w apps/agent"
echo ""
echo "To start the dashboard:"
echo "  npm run dev -w apps/web"
