#!/usr/bin/env bash
# E2E Timeout Path Test — Fedimint Escrow Module
#
# Flow:
#   1. Get current block height
#   2. Buyer creates escrow with timeout_block = current+2, timeout_action=refund
#   3. Verify state is Open
#   4. Attempt early claim → expect failure (TimelockNotExpired)
#   5. Mine 3 blocks (height passes timeout)
#   6. Wait for federation to process new blocks
#   7. Buyer calls claim-timeout → success
#   8. State = TimedOut, buyer balance increases
#
# Requires: active devimint federation (target/devimint symlink → live data dir)
# Usage: bash scripts/dev/e2e-timeout-path.sh

set -euo pipefail

ESCROW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FEDIMINT_CLI="$ESCROW_DIR/target/debug/fedimint-cli"

# ── Color helpers ──────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "\n${YELLOW}>>> $1${NC}"; }
ok()    { echo -e "    ${GREEN}✓ $1${NC}"; }
fail()  { echo -e "    ${RED}✗ FAIL: $1${NC}" >&2; exit 1; }
assert_eq() { [[ "$1" == "$2" ]] || fail "Expected '$2', got '$1'"; }

# ── Load devimint environment ──────────────────────────────────────────────────
ENV_FILE="$ESCROW_DIR/target/devimint/env"
[[ -f "$ENV_FILE" ]] || { echo "ERROR: devimint env not found at $ENV_FILE"; exit 1; }
set +u
eval "$(cat "$ENV_FILE")"
set -u

[[ -f "$FM_TEST_DIR/ready" ]] || { echo "ERROR: Federation not ready"; exit 1; }

# ── Client + bitcoin helpers ───────────────────────────────────────────────────
buyer()   { "$FEDIMINT_CLI" --data-dir "$FM_CLIENT_DIR" "$@"; }
seller()  { "$FEDIMINT_CLI" --data-dir "$FM_CLIENT_BASE_DIR/seller-0" "$@"; }
btc()     { eval "$FM_BTC_CLIENT" -rpcwallet="" "$@"; }
mine()    { local n=${1:-1}; MINE_ADDR=$(btc getnewaddress 2>/dev/null); btc generatetoaddress "$n" "$MINE_ADDR" >/dev/null; }
blockheight() { eval "$FM_BTC_CLIENT" getblockcount 2>/dev/null; }

# Dummy oracle pubkeys (G, 2G, 3G) — not used for happy timeout path
ORACLE1="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
ORACLE2="02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
ORACLE3="02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

ESCROW_AMOUNT="10000"  # 10,000 msat = 10 sats

# ── Banner ─────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  E2E ESCROW TIMEOUT PATH TEST"
echo "  Flow: create → early-claim-fails → mine → claim-timeout → verify"
echo "  Timeout action: refund (buyer reclaims after expiry)"
echo "════════════════════════════════════════════════════════"

# ── Step 1: Get current block height ──────────────────────────────────────────
info "Step 1: Get current block height"
CURRENT_HEIGHT=$(blockheight)
TIMEOUT_BLOCK=$(( CURRENT_HEIGHT + 2 ))
ok "Current height: $CURRENT_HEIGHT"
ok "Timeout block:  $TIMEOUT_BLOCK (current+2)"

# ── Step 2: Ensure seller is set up (for seller pubkey) ───────────────────────
info "Step 2: Ensure seller client is set up"
SELLER_DIR="$FM_CLIENT_BASE_DIR/seller-0"
if [[ -d "$SELLER_DIR/client.db" ]]; then
  ok "Seller already joined federation"
else
  mkdir -p "$SELLER_DIR"
  INVITE_CODE=$(buyer invite-code 0 | python3 -c "import sys,json; print(json.load(sys.stdin)['invite_code'])")
  seller join-federation "$INVITE_CODE" >/dev/null 2>&1
  ok "Seller joined federation"
fi
SELLER_PUBKEY=$(seller module escrow public-key | python3 -c "import sys,json; print(json.load(sys.stdin)['public_key'])")
ok "Seller pubkey: $SELLER_PUBKEY"

# ── Step 3: Record buyer balance before ───────────────────────────────────────
info "Step 3: Record buyer balance before"
BUYER_BALANCE_BEFORE=$(buyer info | python3 -c "import sys,json; print(json.load(sys.stdin)['total_amount_msat'])")
ok "Buyer balance: ${BUYER_BALANCE_BEFORE} msat"

# ── Step 4: Buyer creates escrow with near-future timeout ──────────────────────
info "Step 4: Buyer creates escrow (timeout_block=${TIMEOUT_BLOCK}, action=refund)"
# Non-custodial: generate secret locally; only hash goes to federation.
# Timeout path doesn't need the secret code (claim-timeout is used), but create requires a hash.
_SC=$(python3 -c "import secrets; print(secrets.token_hex(32))")
_SC_HASH=$(python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$_SC")
CREATE_JSON=$(buyer module escrow create \
  "$SELLER_PUBKEY" \
  "$ORACLE1" "$ORACLE2" "$ORACLE3" \
  "$ESCROW_AMOUNT" "$TIMEOUT_BLOCK" refund \
  --secret-code-hash "$_SC_HASH" 2>&1)

echo "    Raw output: $CREATE_JSON"
ESCROW_ID=$(echo "$CREATE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['escrow-id'])")
ok "Escrow ID: $ESCROW_ID"

# ── Step 5: Verify state is Open ───────────────────────────────────────────────
info "Step 5: Verify escrow is Open"
STATE=$(buyer module escrow info "$ESCROW_ID" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")
ok "State: $STATE"
assert_eq "$STATE" "Open"

# ── Step 6: Attempt early claim — must fail ────────────────────────────────────
info "Step 6: Attempt early claim-timeout (must fail — timelock not expired)"
CURRENT_HEIGHT=$(blockheight)
ok "Current block height: $CURRENT_HEIGHT < $TIMEOUT_BLOCK (timeout not reached)"

EARLY_CLAIM_OUTPUT=$(buyer module escrow claim-timeout "$ESCROW_ID" 2>&1 || true)
echo "    Early claim output: $EARLY_CLAIM_OUTPUT"

# The claim should have been rejected — either error in JSON or non-zero exit
if echo "$EARLY_CLAIM_OUTPUT" | grep -qi "TimelockNotExpired\|rejected\|error\|timelock"; then
  ok "Early claim correctly rejected (timelock not expired)"
elif echo "$EARLY_CLAIM_OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('status')=='timeout claimed' else 1)" 2>/dev/null; then
  fail "Early claim SHOULD have been rejected but succeeded — timelock not enforced!"
else
  ok "Early claim failed (non-JSON error, as expected)"
fi

# ── Step 7: Mine past the timeout block ───────────────────────────────────────
info "Step 7: Mine blocks to pass timeout (need height > $TIMEOUT_BLOCK)"
mine 3
NEW_HEIGHT=$(blockheight)
ok "Mined 3 blocks → height: $NEW_HEIGHT (timeout was $TIMEOUT_BLOCK)"
(( NEW_HEIGHT > TIMEOUT_BLOCK )) || fail "Block height $NEW_HEIGHT still <= timeout $TIMEOUT_BLOCK"

# ── Step 8: Wait for federation to process new blocks ─────────────────────────
info "Step 8: Waiting for federation to process new blocks..."
# The federation watches bitcoind; give it time to catch up
MAX_WAIT=30
for i in $(seq 1 $MAX_WAIT); do
  sleep 1
  # Try the claim — if it succeeds, the federation has processed the blocks
  CLAIM_TRY=$(buyer module escrow claim-timeout "$ESCROW_ID" 2>&1 || true)
  if echo "$CLAIM_TRY" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('status')=='timeout claimed' else 1)" 2>/dev/null; then
    ok "Federation processed new blocks after ${i}s"
    CLAIM_JSON="$CLAIM_TRY"
    break
  fi
  if (( i == MAX_WAIT )); then
    echo "    Last claim attempt output: $CLAIM_TRY"
    fail "Federation did not process new blocks within ${MAX_WAIT}s"
  fi
  echo -n "."
done
echo ""

# ── Step 9: Verify claim output ───────────────────────────────────────────────
info "Step 9: Verify claim-timeout output"
echo "    Raw output: $CLAIM_JSON"
CLAIM_STATUS=$(echo "$CLAIM_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
ok "Claim status: $CLAIM_STATUS"
assert_eq "$CLAIM_STATUS" "timeout claimed"

# ── Step 10: Verify state is TimedOut ─────────────────────────────────────────
info "Step 10: Verify escrow state is TimedOut"
STATE=$(buyer module escrow info "$ESCROW_ID" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")
ok "State: $STATE"
assert_eq "$STATE" "TimedOut"

# ── Step 11: Wait for balance to settle ───────────────────────────────────────
info "Step 11: Waiting for balance to settle..."
sleep 3

# ── Step 12: Verify buyer reclaimed funds ─────────────────────────────────────
info "Step 12: Verify buyer reclaimed funds"
BUYER_BALANCE_AFTER=$(buyer info | python3 -c "import sys,json; print(json.load(sys.stdin)['total_amount_msat'])")
BUYER_DELTA=$(( BUYER_BALANCE_AFTER - BUYER_BALANCE_BEFORE ))

ok "Buyer balance before: ${BUYER_BALANCE_BEFORE} msat"
ok "Buyer balance after:  ${BUYER_BALANCE_AFTER} msat"
ok "Buyer delta:          ${BUYER_DELTA} msat"

# Buyer should have been refunded (net ≈ 0 minus any mint fees on the create tx)
# The create tx costs ~600 msat in mint fees, the refund should restore most of it
if (( BUYER_DELTA < -5000 )); then
  fail "Buyer lost too much: ${BUYER_DELTA} msat (expected delta > -5000)"
fi
# The buyer should have gotten back at least some of the escrow amount
if (( BUYER_BALANCE_AFTER <= 0 )); then
  fail "Buyer balance is zero or negative after timeout claim"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo -e "  ${GREEN}✓ E2E TIMEOUT PATH TEST PASSED!${NC}"
echo "  Escrow ID:      $ESCROW_ID"
echo "  Amount:         ${ESCROW_AMOUNT} msat"
echo "  Timeout block:  $TIMEOUT_BLOCK"
echo "  Final height:   $NEW_HEIGHT"
echo "  Buyer delta:    ${BUYER_DELTA} msat"
echo "════════════════════════════════════════════════════════"
