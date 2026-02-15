#!/bin/bash

# Configuration
OSSEC_CONF="/var/ossec/etc/ossec.conf"
WEBHOOK_URL="http://127.0.0.1:3000/wazuh-alert"

if [ ! -f "$OSSEC_CONF" ]; then
    echo "Error: $OSSEC_CONF not found. Is Wazuh installed?"
    exit 1
fi

echo "Configuring Wazuh Webhook Integration..."

# Check if integration already exists
if grep -q "$WEBHOOK_URL" "$OSSEC_CONF"; then
    echo "Webhook already configured."
else
    # Backup
    cp "$OSSEC_CONF" "${OSSEC_CONF}.bak"
    
    # Inject integration block before </ossec_config>
    sed -i "/<\/ossec_config>/i \\
  <integration>\\
    <name>custom-webhook</name>\\
    <hook_url>$WEBHOOK_URL</hook_url>\\
    <alert_format>json</alert_format>\\
  </integration>" "$OSSEC_CONF"
    
    echo "Webhook configuration added."
    
    # Enable jsonout if not enabled (usually default yes, but good to ensure)
    sed -i 's/<jsonout_output>no<\/jsonout_output>/<jsonout_output>yes<\/jsonout_output>/' "$OSSEC_CONF"

    # Restart Wazuh Manager
    systemctl restart wazuh-manager
    echo "Wazuh Manager restarted."
fi
