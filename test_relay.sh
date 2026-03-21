#!/usr/bin/env bash
# test_relay.sh — Local integration test for the p2ptexter bootstrap/relay server
# Usage:   ./test_relay.sh
# Prereqs: bootstrap_server compiled via `cargo build` inside bootstrap_server/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP_DIR="$SCRIPT_DIR/bootstrap_server"
BOOTSTRAP_BIN="$BOOTSTRAP_DIR/target/debug/bootstrap"
BASE_URL="http://127.0.0.1:3000"
LOG=/tmp/bootstrap_test.log

# ── colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}  ✓ PASS${NC} $*"; }
fail() { echo -e "${RED}  ✗ FAIL${NC} $*"; FAILURES=$((FAILURES+1)); }
info() { echo -e "${YELLOW}  ▶${NC} $*"; }

FAILURES=0

# ── compile if missing ────────────────────────────────────────────────────────
if [ ! -f "$BOOTSTRAP_BIN" ]; then
    info "Bootstrap binary not found — building..."
    cd "$BOOTSTRAP_DIR" && cargo build 2>&1
    cd "$SCRIPT_DIR"
fi

# ── kill any stale process on port 3000 ───────────────────────────────────────
pkill -f "target/debug/bootstrap" 2>/dev/null || true
sleep 0.5

# ── start server ──────────────────────────────────────────────────────────────
info "Starting bootstrap server..."
"$BOOTSTRAP_BIN" > "$LOG" 2>&1 &
BS_PID=$!

cleanup() {
    kill $BS_PID 2>/dev/null || true
    wait $BS_PID 2>/dev/null || true
}
trap cleanup EXIT

# Wait for HTTP + libp2p to be ready (poll /bootstrap/info via POST)
info "Waiting for server to be ready (up to 15s)..."
for i in $(seq 1 30); do
    if curl -sf -X POST "$BASE_URL/bootstrap/info" > /dev/null 2>&1; then
        echo "  Server ready after ~$((i/2))s"
        break
    fi
    sleep 0.5
    if [ $i -eq 30 ]; then
        fail "Server did not start within 15s"
        echo "=== bootstrap log ==="
        cat "$LOG"
        exit 1
    fi
done

echo ""
echo "════════════════════════════════════════════════"
echo " HTTP API Tests"
echo "════════════════════════════════════════════════"

# ── Test 1: /bootstrap/info ───────────────────────────────────────────────────
info "Test 1: POST /bootstrap/info"
INFO=$(curl -sf -X POST "$BASE_URL/bootstrap/info")
if echo "$INFO" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d and 'peer_id' in d and d['peer_id'].startswith('12D3')
" 2>/dev/null; then
    PEER_ID=$(echo "$INFO" | python3 -c "import sys,json; print(json.load(sys.stdin)['peer_id'])")
    MULTIADDR=$(echo "$INFO" | python3 -c "import sys,json; print(json.load(sys.stdin)['multiaddr'])")
    pass "/bootstrap/info → peer_id=$PEER_ID"
    pass "             → multiaddr=$MULTIADDR"
else
    fail "/bootstrap/info returned unexpected: $INFO"
    PEER_ID=""
    MULTIADDR=""
fi

# ── Test 2: /register ─────────────────────────────────────────────────────────
info "Test 2: POST /register"
STATUS=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d '{"peer_id":"test_peer_abc"}')
[ "$STATUS" = "200" ] && pass "/register → 200" || fail "/register → $STATUS (expected 200)"

# ── Test 3: /qr/generate ──────────────────────────────────────────────────────
info "Test 3: POST /qr/generate"
QR_RES=$(curl -sf -X POST "$BASE_URL/qr/generate" \
    -H "Content-Type: application/json" \
    -d '{"peer_id":"abc123:def456","validity_secs":300}')
if echo "$QR_RES" | python3 -c "
import sys,json; d=json.load(sys.stdin); assert 'encrypted_token' in d
" 2>/dev/null; then
    TOKEN=$(echo "$QR_RES" | python3 -c "import sys,json; print(json.load(sys.stdin)['encrypted_token'])")
    pass "/qr/generate produced token (len=${#TOKEN})"
else
    fail "/qr/generate → $QR_RES"
    TOKEN=""
fi

# ── Test 4: /qr/scan (valid token) ───────────────────────────────────────────
info "Test 4: POST /qr/scan (valid token)"
if [ -n "$TOKEN" ]; then
    SCAN=$(curl -sf -X POST "$BASE_URL/qr/scan" \
        -H "Content-Type: application/json" \
        -d "{\"scanner_peer_id\":\"scanner_peer\",\"encrypted_token\":\"$TOKEN\"}")
    if echo "$SCAN" | python3 -c "import sys,json; assert json.load(sys.stdin).get('success')" 2>/dev/null; then
        pass "/qr/scan accepted valid token"
    else
        fail "/qr/scan: $SCAN"
    fi
else
    fail "/qr/scan skipped — no token from previous test"
fi

# ── Test 5: /qr/scan (invalid token) ─────────────────────────────────────────
info "Test 5: POST /qr/scan (bad token)"
BAD=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/qr/scan" \
    -H "Content-Type: application/json" \
    -d '{"scanner_peer_id":"bad_peer","encrypted_token":"!!!notvalid!!!"}')
[ "$BAD" = "400" ] && pass "/qr/scan rejected bad token → 400" || fail "/qr/scan bad token → $BAD (expected 400)"

# ── Test 6: /peer/ip (strangers) ──────────────────────────────────────────────
info "Test 6: POST /peer/ip (non-friends — expect 403)"
IP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/peer/ip" \
    -H "Content-Type: application/json" \
    -d '{"requester_peer_id":"stranger","target_peer_id":"test_peer_abc"}')
[ "$IP_STATUS" = "403" ] && pass "/peer/ip denied non-friend → 403" || fail "/peer/ip → $IP_STATUS (expected 403)"

# ── Test 7: /peer/ping + /peer/status round-trip ─────────────────────────────
info "Test 7: POST /peer/ping + /peer/status (offline ping round-trip)"
PING=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/peer/ping" \
    -H "Content-Type: application/json" \
    -d '{"sender_peer_id":"alice","target_peer_id":"bob"}')
[ "$PING" = "200" ] && pass "/peer/ping accepted → 200" || fail "/peer/ping → $PING"

STATUS_RES=$(curl -sf -X POST "$BASE_URL/peer/status" \
    -H "Content-Type: application/json" \
    -d '{"peer_id":"bob"}')
if echo "$STATUS_RES" | python3 -c "
import sys,json; d=json.load(sys.stdin); assert 'alice' in d.get('unread_from',[])
" 2>/dev/null; then
    pass "/peer/status shows alice's pending ping"
else
    fail "/peer/status: $STATUS_RES"
fi

echo ""
echo "════════════════════════════════════════════════"
echo " libp2p / Relay Tests"
echo "════════════════════════════════════════════════"

# ── Test 8: TCP 4001 open ─────────────────────────────────────────────────────
info "Test 8: libp2p TCP port 4001 reachable"
if timeout 3 bash -c "echo > /dev/tcp/127.0.0.1/4001" 2>/dev/null; then
    pass "TCP 4001 is open (libp2p accepting connections)"
else
    fail "TCP 4001 not reachable — libp2p may not have bound"
fi

# ── Test 9: Multiaddr format ──────────────────────────────────────────────────
info "Test 9: Reported multiaddr format"
if [ -n "$MULTIADDR" ] && echo "$MULTIADDR" | grep -qE "^/ip4/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/(tcp|udp)/[0-9]+"; then
    pass "Multiaddr is a valid libp2p format: $MULTIADDR"
else
    fail "Multiaddr format unexpected: '$MULTIADDR'"
fi

# ── Test 10: Stable PeerId ────────────────────────────────────────────────────
info "Test 10: PeerId persistence (p2p_identity.key)"
if [ -f "$BOOTSTRAP_DIR/p2p_identity.key" ]; then
    pass "p2p_identity.key exists — PeerId is stable across restarts"
else
    fail "p2p_identity.key MISSING — PeerId will change on every restart!"
fi

echo ""
echo "════════════════════════════════════════════════"
echo " Relay Messaging Tests"
echo "════════════════════════════════════════════════"

TEST_P2P_BIN="$BOOTSTRAP_DIR/target/debug/test_p2p"

# Build test_p2p if needed
if [ ! -f "$TEST_P2P_BIN" ]; then
    info "Building test_p2p binary..."
    cd "$BOOTSTRAP_DIR" && cargo build --bin test_p2p 2>&1 | tail -5
    cd "$SCRIPT_DIR"
fi

# ── Test 11: Alice registers relay reservation ────────────────────────────────
# ── Test 12: Bob sends message to Alice through relay ─────────────────────────
info "Tests 11-12: Two peers communicate via relay circuit (30s timeout)"
echo "  (Alice reserves relay slot, Bob dials through circuit, message exchanged)"
P2P_OUT=$("$TEST_P2P_BIN" --url "$BASE_URL" 2>&1)
P2P_EXIT=$?

echo "$P2P_OUT" | while IFS= read -r line; do
    echo "    $line"
done

if [ $P2P_EXIT -eq 0 ]; then
    pass "Test 11: Alice received Bob's message through relay"
    pass "Test 12: Bob received Alice's response through relay"
else
    fail "Test 11: Relay reservation or message send failed"
    fail "Test 12: Relay message round-trip did not complete"
fi

echo ""
echo "════════════════════════════════════════════════"
TOTAL=12
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}  All $TOTAL tests passed! ✓${NC}"
else
    echo -e "${RED}  $FAILURES / $TOTAL test(s) FAILED ✗${NC}"
    echo ""
    echo "=== bootstrap server log (last 30 lines) ==="
    tail -30 "$LOG"
fi
echo "════════════════════════════════════════════════"
exit $FAILURES
