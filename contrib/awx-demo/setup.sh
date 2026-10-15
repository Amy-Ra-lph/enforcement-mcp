#!/bin/bash
# AWX + aap-mcp-server deployment
# Deploys AWX via k3s + operator on a Beaker host, then sets up aap-mcp-server.
#
# Usage: ./setup.sh <target-host> [admin-password]
# Example: ./setup.sh sweetpig-1.khw.eng.rdu2.dc.redhat.com Agentic2026!
set -euo pipefail

TARGET="${1:?Usage: $0 <target-host> [admin-password]}"
PASSWORD="${2:-Agentic2026!}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Deploying AWX to $TARGET ==="

# Step 1: Deploy AWX + aap-mcp-server
ansible-playbook "$SCRIPT_DIR/deploy-awx.yml" \
    -i "$TARGET," \
    -e "awx_admin_password=$PASSWORD" \
    -u root

echo ""
echo "=== Configuring job templates ==="

# Get token
TOKEN=$(curl -sf -X POST "http://$TARGET:30080/api/v2/tokens/" \
    -H "Content-Type: application/json" \
    -u "admin:$PASSWORD" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Step 2: Configure templates
ansible-playbook "$SCRIPT_DIR/configure-templates.yml" \
    -i "$TARGET," \
    -e "awx_token=$TOKEN" \
    -u root

echo ""
echo "=== Distributing SSH key ==="
PUBKEY=$(ssh root@"$TARGET" 'cat /root/.ssh/id_ed25519.pub')
echo "Add this key to managed hosts' /root/.ssh/authorized_keys:"
echo "  $PUBKEY"

echo ""
echo "=============================================="
echo "  AWX Demo Stack Ready"
echo "=============================================="
echo ""
echo "  AWX UI:         http://$TARGET:30080"
echo "  AWX Login:      admin / $PASSWORD"
echo "  aap-mcp-server: http://$TARGET:3000/mcp"
echo "  Auth token:     $TOKEN"
echo ""
echo "  Claude Code MCP config:"
echo "  {"
echo "    \"aap-mcp\": {"
echo "      \"type\": \"http\","
echo "      \"url\": \"http://$TARGET:3000/mcp\","
echo "      \"headers\": {\"Authorization\": \"Bearer $TOKEN\"}"
echo "    }"
echo "  }"
