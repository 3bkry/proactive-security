
#!/bin/bash

# ─────────────────────────────────────────────────────────────
# SentinelAI Installer — System-Wide Edition
# ─────────────────────────────────────────────────────────────

# Color Constants
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Installation paths
INSTALL_DIR="/opt/sentinel-agent"
BIN_LINK="/usr/local/bin/sentinelctl"
CONFIG_DIR="/etc/sentinel-agent"
LOG_DIR="/var/log/sentinel-agent"
DATA_DIR="/var/lib/sentinel-agent"
SENTINEL_GROUP="sentinel"

echo -e "${BLUE}"
echo "   ____                   _     _                  _      _  "
echo "  / ___|    ___   _ __   | |_  (_)  _ __     ___  | |    / \\ "
echo "  \\___ \\   / _ \\ | '_ \\  | __| | | | '_ \\   / _ \\ | |   / _ \\  "
echo "   ___) | |  __/ | | | | | |_  | | | | | | |  __/ | |  / ___ \\ "
echo "  |____/   \\___| |_| |_|  \\__| |_| |_| |_|  \\___| |_| /_/   \\_\\"
echo "                                                                  "
echo -e "${NC}"
echo -e "${BLUE}System Security & Threat Detection Agent Installer${NC}"
echo -e "${YELLOW}Mode: System-wide installation (/opt)${NC}"
echo ""

# ── Root check (hard requirement for system-wide install) ────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✖  This installer must be run as root or with sudo.${NC}"
    echo -e "   Usage: ${BLUE}sudo bash install.sh${NC}"
    exit 1
fi

# ── Detect the real invoking user (for messages, not permissions) ──
REAL_USER="${SUDO_USER:-root}"
echo -e "${GREEN}▶ Installing as root. CLI will be available to ALL users.${NC}"
echo ""

# ─────────────────────────────────────────────────────────────
# 1. Dependencies
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}🔍 Checking dependencies...${NC}"

install_pkg() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "   Installing ${YELLOW}$1${NC}..."
        apt-get install -y "$2" >/dev/null 2>&1 || {
            echo -e "${RED}   ✖ Failed to install $2${NC}"; exit 1;
        }
    else
        echo -e "   ${GREEN}✔${NC} $1 found"
    fi
}

# Update package lists once
apt-get update -qq

# Node.js
if ! command -v node &>/dev/null; then
    echo -e "   Installing ${YELLOW}Node.js 20.x${NC}..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
    apt-get install -y nodejs >/dev/null 2>&1
else
    NODE_VER=$(node -v)
    echo -e "   ${GREEN}✔${NC} Node.js ${NODE_VER} found"
fi

install_pkg "iptables" "iptables"
install_pkg "git"      "git"

echo ""

# ─────────────────────────────────────────────────────────────
# 2. Create sentinel group (for shared access)
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}👥 Setting up 'sentinel' system group...${NC}"

if ! getent group "$SENTINEL_GROUP" >/dev/null 2>&1; then
    groupadd --system "$SENTINEL_GROUP"
    echo -e "   Created group ${YELLOW}${SENTINEL_GROUP}${NC}"
else
    echo -e "   ${GREEN}✔${NC} Group '${SENTINEL_GROUP}' already exists"
fi

# Add the invoking user to the group (if not root itself)
if [ "$REAL_USER" != "root" ]; then
    usermod -aG "$SENTINEL_GROUP" "$REAL_USER"
    echo -e "   Added ${YELLOW}${REAL_USER}${NC} to group '${SENTINEL_GROUP}'"
fi

echo ""

# ─────────────────────────────────────────────────────────────
# 3. Clone / Update source
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}⬇️  Cloning SentinelAI → ${INSTALL_DIR}${NC}"

if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "   Existing installation found — pulling latest..."
    cd "$INSTALL_DIR"
    git pull --ff-only || {
        echo -e "${YELLOW}   ⚠ Git pull failed; continuing with existing code.${NC}"
    }
else
    rm -rf "$INSTALL_DIR"
    git clone https://github.com/3bkry/proactive-security.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo ""

# ─────────────────────────────────────────────────────────────
# 4. Install & Build
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}📦 Installing packages...${NC}"
npm install --production=false 2>&1 | tail -1

echo -e "${GREEN}🔨 Building...${NC}"
npm run build -w packages/core   2>&1 | tail -1
npm run build -w packages/cli    2>&1 | tail -1
npm run build -w apps/agent      2>&1 | tail -1

echo ""

# ─────────────────────────────────────────────────────────────
# 5. Create system directories
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}📁 Creating system directories...${NC}"

mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"

# Ownership & permissions:
#   /opt/sentinel-agent  → root:sentinel  r-x for group (read + execute, no write)
#   /etc/sentinel-agent  → root:sentinel  rwx for group (users can run setup)
#   /var/log/sentinel-*  → root:sentinel  rwx for group
#   /var/lib/sentinel-*  → root:sentinel  rwx for group
chown -R root:"$SENTINEL_GROUP" "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"

chown -R root:"$SENTINEL_GROUP" "$CONFIG_DIR"
chmod -R 775 "$CONFIG_DIR"

chown -R root:"$SENTINEL_GROUP" "$LOG_DIR"
chmod -R 775 "$LOG_DIR"

chown -R root:"$SENTINEL_GROUP" "$DATA_DIR"
chmod -R 775 "$DATA_DIR"

echo -e "   ${GREEN}✔${NC} $CONFIG_DIR (config)"
echo -e "   ${GREEN}✔${NC} $LOG_DIR    (logs)"
echo -e "   ${GREEN}✔${NC} $DATA_DIR   (runtime data)"

echo ""

# ─────────────────────────────────────────────────────────────
# 6. Create global wrapper script
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}🔗 Installing sentinelctl globally → ${BIN_LINK}${NC}"

# Determine the actual CLI entry point inside the project.
# Adjust the path below if your packages/cli exposes a different bin.
CLI_ENTRY="${INSTALL_DIR}/packages/cli/dist/index.js"

# Fallback: if there's a bin field in packages/cli/package.json, try to
# resolve it. Otherwise we use the dist/index.js convention.
if [ -f "${INSTALL_DIR}/packages/cli/package.json" ]; then
    PKG_BIN=$(node -e "
        const p = require('${INSTALL_DIR}/packages/cli/package.json');
        const b = p.bin;
        if (typeof b === 'string') console.log(b);
        else if (b && b.sentinelctl) console.log(b.sentinelctl);
    " 2>/dev/null)
    if [ -n "$PKG_BIN" ]; then
        CLI_ENTRY="${INSTALL_DIR}/packages/cli/${PKG_BIN}"
    fi
fi

cat > "$BIN_LINK" <<WRAPPER
#!/usr/bin/env bash
# ── SentinelAI CLI wrapper (auto-generated) ──
export SENTINEL_INSTALL_DIR="${INSTALL_DIR}"
export SENTINEL_CONFIG_DIR="${CONFIG_DIR}"
export SENTINEL_LOG_DIR="${LOG_DIR}"
export SENTINEL_DATA_DIR="${DATA_DIR}"
exec node "${CLI_ENTRY}" "\$@"
WRAPPER

chmod 755 "$BIN_LINK"
echo -e "   ${GREEN}✔${NC} Any user can now run: ${BLUE}sentinelctl${NC}"

echo ""

# ─────────────────────────────────────────────────────────────
# 7. Sudoers — allow sentinel group to run iptables
# ─────────────────────────────────────────────────────────────
echo -e "${BLUE}🛡️  Configuring iptables permissions (sudoers)...${NC}"

SUDOERS_FILE="/etc/sudoers.d/sentinel-ban"

cat > "$SUDOERS_FILE" <<SUDOERS
# SentinelAI — allow members of '${SENTINEL_GROUP}' to manage iptables
# without a password, for automated IP banning / unbanning.
%${SENTINEL_GROUP} ALL=(ALL) NOPASSWD: /usr/sbin/iptables
SUDOERS

chmod 0440 "$SUDOERS_FILE"

# Validate the sudoers file
if visudo -cf "$SUDOERS_FILE" >/dev/null 2>&1; then
    echo -e "   ${GREEN}✔${NC} Sudoers rule installed and validated"
else
    echo -e "   ${RED}✖ Sudoers syntax error — removing bad file${NC}"
    rm -f "$SUDOERS_FILE"
    echo -e "   ${YELLOW}⚠ You will need to configure iptables permissions manually.${NC}"
fi

echo ""

# ─────────────────────────────────────────────────────────────
# 8. Optional: systemd service
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}⚙️  Installing systemd service...${NC}"

AGENT_ENTRY="${INSTALL_DIR}/apps/agent/dist/index.js"

cat > /etc/systemd/system/sentinel-agent.service <<SERVICE
[Unit]
Description=SentinelAI Proactive Security Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env node ${AGENT_ENTRY}
WorkingDirectory=${INSTALL_DIR}
Restart=on-failure
RestartSec=10

# Security hardening
Environment=NODE_ENV=production
Environment=SENTINEL_CONFIG_DIR=${CONFIG_DIR}
Environment=SENTINEL_LOG_DIR=${LOG_DIR}
Environment=SENTINEL_DATA_DIR=${DATA_DIR}

# Run as root so iptables works directly (the agent itself handles permissions)
User=root
Group=${SENTINEL_GROUP}

# Logging
StandardOutput=append:${LOG_DIR}/agent.log
StandardError=append:${LOG_DIR}/agent-error.log

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
echo -e "   ${GREEN}✔${NC} Service installed: ${BLUE}sentinel-agent.service${NC}"
echo -e "   Enable on boot with: ${BLUE}sudo systemctl enable sentinel-agent${NC}"

echo ""

# ─────────────────────────────────────────────────────────────
# 9. Add all existing human users to sentinel group (optional)
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}👥 Adding existing users to '${SENTINEL_GROUP}' group...${NC}"

# Add all human users (UID ≥ 1000, with a real shell) to the group
while IFS=: read -r username _ uid _ _ _ shell; do
    if [ "$uid" -ge 1000 ] && [[ "$shell" == */bash || "$shell" == */zsh || "$shell" == */sh || "$shell" == */fish ]]; then
        if ! id -nG "$username" 2>/dev/null | grep -qw "$SENTINEL_GROUP"; then
            usermod -aG "$SENTINEL_GROUP" "$username"
            echo -e "   Added ${YELLOW}${username}${NC}"
        else
            echo -e "   ${GREEN}✔${NC} ${username} (already member)"
        fi
    fi
done < /etc/passwd

echo ""

# ─────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅  SentinelAI installed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Install dir  : ${BLUE}${INSTALL_DIR}${NC}"
echo -e "  Config dir   : ${BLUE}${CONFIG_DIR}${NC}"
echo -e "  Log dir      : ${BLUE}${LOG_DIR}${NC}"
echo -e "  CLI binary   : ${BLUE}${BIN_LINK}${NC}"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo -e "    1. Run ${BLUE}sentinelctl setup${NC}    — configure API keys & Telegram"
echo -e "    2. Run ${BLUE}sentinelctl start${NC}    — launch the agent"
echo -e "       or  ${BLUE}sudo systemctl start sentinel-agent${NC}"
echo ""
echo -e "  ${YELLOW}Note:${NC} Users may need to log out & back in for the"
echo -e "  '${SENTINEL_GROUP}' group membership to take effect."
echo ""
