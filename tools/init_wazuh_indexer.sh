#!/bin/bash
set -e

# Color Constants
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🔐 Initializing Wazuh Indexer Security...${NC}"

# Correct path for Wazuh Indexer 4.7.2
SECURITY_SCRIPT="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh"

# Ensure script is executable and run it with JAVA_HOME set
docker exec wazuh.indexer bash -c "export JAVA_HOME=/usr/share/wazuh-indexer/jdk && \
chmod +x $SECURITY_SCRIPT && $SECURITY_SCRIPT \
  -cd /usr/share/wazuh-indexer/opensearch-security/securityconfig/ \
  -icl -nhnv \
  -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
  -cert /usr/share/wazuh-indexer/certs/admin.pem \
  -key /usr/share/wazuh-indexer/certs/admin-key.pem"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✔ Security Index Initialized Successfully!${NC}"
    echo -e "   The Dashboard should be accessible at https://<server-ip>:4443 in a few moments."
else
    echo -e "${RED}✖ Initialization failed.${NC}"
    exit 1
fi
