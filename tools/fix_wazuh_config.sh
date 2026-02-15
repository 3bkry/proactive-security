#!/bin/bash
set -e

# Color Constants
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

INSTALL_DIR="/opt/sentinel-agent"
WAZUH_DIR="${INSTALL_DIR}/wazuh"
CONFIG_FILE="${WAZUH_DIR}/ossec.conf"

echo -e "${GREEN}🔧 Fixing Wazuh Configuration...${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✖ Please run as root (sudo).${NC}"
    exit 1
fi

if ! command -v docker &>/dev/null; then
    echo -e "${RED}✖ Docker not found.${NC}"
    exit 1
fi

mkdir -p "$WAZUH_DIR"

# 1. Extract default config from fresh image
echo -e "   Extracting default configuration..."
docker run --rm --entrypoint cat wazuh/wazuh-manager:4.7.2 /var/ossec/etc/ossec.conf > "${CONFIG_FILE}.default"

# 2. Prepare Integration Block
INTEGRATION_BLOCK='
  <!-- SentinelAI Webhook Integration -->
  <integration>
    <name>custom-webhook</name>
    <hook_url>http://172.17.0.1:3000/wazuh-alert</hook_url>
    <level>3</level>
    <json>yes</json>
    <alert_format>json</alert_format>
  </integration>

  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
'

# 3. Inject Integration (Insert before <global>)
# We replace the first instance of <global> with our block + <global>
# This ensures we are inside ossec_config but before other settings
# Actually, just appending it inside <ossec_config> is safer if we handle the closing tag.

# Strategy: Remove the last line </ossec_config>, append integration, add </ossec_config> back.
head -n -1 "${CONFIG_FILE}.default" > "$CONFIG_FILE"

cat >> "$CONFIG_FILE" <<EOF

  <!-- SentinelAI Webhook Integration -->
  <integration>
    <name>custom-webhook</name>
    <hook_url>http://172.17.0.1:3000/wazuh-alert</hook_url>
    <level>3</level>
    <json>yes</json>
    <alert_format>json</alert_format>
  </integration>

</ossec_config>
EOF

# 4. Restart Manager
echo -e "   Restarting Wazuh Manager..."
cd "$INSTALL_DIR"
if command -v docker-compose &>/dev/null; then
    docker-compose restart wazuh.manager
else
    docker compose restart wazuh.manager
fi

echo -e "${GREEN}✅ Configuration fixed! Standard rules are now active.${NC}"
echo -e "   Please wait ~30s for the manager to reload."
