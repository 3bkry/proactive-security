
#!/bin/bash

# COlOR Constants
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}
  ____                   _     _                  _      _ 
 / ___|    ___   _ __   | |_  (_)  _ __     ___  | |    / \ 
 \___ \   / _ \ | '_ \  | __| | | | '_ \   / _ \ | |   / _ \ 
  ___) | |  __/ | | | | | |_  | | | | | | |  __/ | |  / ___ \ 
 |____/   \___| |_| |_|  \__| |_| |_| |_|  \___| |_| /_/   \_\ 
                                                                  
${NC}"
echo -e "${BLUE}System Security & Threat Detection Agent Installer${NC}"
echo ""

# Check for root/sudo
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}Please run as root or with sudo to install system dependencies.${NC}"
  # We continue because the user might just be installing locally, but warn them.
fi

echo -e "${GREEN}🔍 Checking dependencies...${NC}"

if ! command -v node &> /dev/null; then
    echo "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

if ! command -v iptables &> /dev/null; then
    echo "Installing iptables..."
    sudo apt-get install -y iptables
fi

echo -e "${GREEN}⬇️  Cloning SentinelAI...${NC}"
git clone https://github.com/3bkry/proactive-security.git sentinel-agent
cd sentinel-agent

echo -e "${GREEN}📦 Installing packages...${NC}"
npm install

echo -e "${GREEN}🔨 Building...${NC}"
npm run build -w packages/core
npm run build -w packages/cli
npm run build -w apps/agent

# Link CLI
echo -e "${GREEN}🔗 Linking CLI...${NC}"
npm link -w packages/cli

# Configure sudoers for banning
echo -e "${BLUE}🛡️  Configuring 'active defense' permissions...${NC}"
if [ -f /etc/sudoers.d/sentinel-ban ]; then
    echo "Permissions already configured."
else
    # Get the actual user who invoked sudo (if available) or current user
    REAL_USER=${SUDO_USER:-$USER}
    echo "$REAL_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables" | sudo tee /etc/sudoers.d/sentinel-ban > /dev/null
    echo -e "Granted passwordless iptables access to $REAL_USER for automated banning."
fi

echo -e "${GREEN}✅ Installation Complete!${NC}"
echo ""
echo -e "Run ${BLUE}sentinelctl setup${NC} to start."
