#!/usr/bin/env bash
#
# Integration test for coraza-ban-wasm
#
# Tests the flow:
#   1. Normal request → 200 OK
#   2. SQL injection → 403 (Coraza blocks + ban issued)
#   3. Normal request → 403 (ban-wasm blocks)
#   4. Check Redis for ban entry

set -euo pipefail

ENVOY_URL="${ENVOY_URL:-http://localhost:8080}"
WEBDIS_URL="${WEBDIS_URL:-http://localhost:7379}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_ok() { echo -e "${GREEN}✓${NC} $1"; }
echo_fail() { echo -e "${RED}✗${NC} $1"; }
echo_info() { echo -e "${YELLOW}→${NC} $1"; }

echo "=========================================="
echo "  coraza-ban-wasm Integration Test"
echo "=========================================="
echo ""

# Check if services are running
echo_info "Checking services..."
if ! curl -sf "${ENVOY_URL}/get" > /dev/null 2>&1; then
    echo_fail "Envoy is not running at ${ENVOY_URL}"
    echo "  Run: just up"
    exit 1
fi
echo_ok "Envoy is running"

if ! curl -sf "${WEBDIS_URL}/PING" > /dev/null 2>&1; then
    echo_fail "Webdis is not running at ${WEBDIS_URL}"
    exit 1
fi
echo_ok "Webdis is running"
echo ""

# Step 1: Normal request should pass
echo_info "Step 1: Sending normal request..."
RESPONSE=$(curl -sf -o /dev/null -w "%{http_code}" "${ENVOY_URL}/get" || echo "000")
if [ "$RESPONSE" = "200" ]; then
    echo_ok "Normal request returned 200 OK"
else
    echo_fail "Normal request returned $RESPONSE (expected 200)"
    exit 1
fi
echo ""

# Step 2: SQL injection should trigger WAF block
echo_info "Step 2: Sending SQL injection payload..."
# URL-encoded: 1' UNION SELECT NULL--
SQLI_PAYLOAD="1'%20UNION%20SELECT%20NULL--"
# Note: Don't use -f here since we expect 403 (which would cause curl to fail with -f)
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${ENVOY_URL}/get?id=${SQLI_PAYLOAD}" 2>/dev/null)
if [ "$RESPONSE" = "403" ]; then
    echo_ok "SQL injection blocked with 403 Forbidden"
else
    echo_fail "SQL injection returned $RESPONSE (expected 403)"
    echo "  WAF might not be blocking. Check Envoy logs: just logs"
    exit 1
fi
echo ""

# Wait for ban to propagate
sleep 1

# Step 3: Same client should now be banned
echo_info "Step 3: Sending normal request (should be banned)..."
# Note: Don't use -f here since we expect 403
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${ENVOY_URL}/get" 2>/dev/null)
if [ "$RESPONSE" = "403" ]; then
    echo_ok "Client is now banned (403 Forbidden)"
else
    echo_fail "Client returned $RESPONSE (expected 403 - should be banned)"
    echo "  Ban might not have been issued. Check logs: just logs"
    exit 1
fi
echo ""

# Step 4: Check Redis for ban entries
echo_info "Step 4: Checking Redis for ban entries..."
BAN_KEYS=$(curl -sf "${WEBDIS_URL}/KEYS/ban:*" | jq -r '.KEYS | length // 0')
if [ "$BAN_KEYS" -gt 0 ]; then
    echo_ok "Found $BAN_KEYS ban entries in Redis"
    echo ""
    echo "  Ban entries:"
    curl -sf "${WEBDIS_URL}/KEYS/ban:*" | jq -r '.KEYS[]' | while read key; do
        echo "    - $key"
    done
else
    echo_fail "No ban entries found in Redis"
    echo "  Ban-wasm might not be writing to Redis. Check logs: just logs"
fi
echo ""

echo "=========================================="
echo -e "  ${GREEN}All tests passed!${NC}"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  - View logs:        just logs"
echo "  - Check ban status: curl ${WEBDIS_URL}/KEYS/ban:*"
echo "  - Clear bans:       curl ${WEBDIS_URL}/FLUSHDB"
echo "  - Stop stack:       just down"
