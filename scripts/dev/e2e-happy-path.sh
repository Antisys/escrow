#!/usr/bin/env bash
# E2E Happy Path Test — Fedimint Escrow Module
#
# Flow: buyer creates escrow → check state is Open → seller claims with secret code → verify seller balance
#
# Requires: active devimint federation (target/devimint symlink must point to live data dir)
# Usage: bash scripts/dev/e2e-happy-path.sh

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
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: devimint env not found at $ENV_FILE"
  echo "  Start the federation first with: bash scripts/dev/launch-devimint.sh"
  exit 1
fi
set +u
eval "$(cat "$ENV_FILE")"
set -u

# Check federation is ready
if [[ ! -f "$FM_TEST_DIR/ready" ]]; then
  echo "ERROR: Federation not ready (no 'ready' file in $FM_TEST_DIR)"
  exit 1
fi

# ── Client helpers ─────────────────────────────────────────────────────────────
buyer()  { "$FEDIMINT_CLI" --data-dir "$FM_CLIENT_DIR" "$@"; }
seller() { "$FEDIMINT_CLI" --data-dir "$FM_CLIENT_BASE_DIR/seller-0" "$@"; }

# ── Oracle test keys (secp256k1: G, 2G, 3G) ───────────────────────────────────
# These are valid compressed public keys used as dummy oracle pubkeys.
# For the happy path (no dispute), oracle keys are never used for verification.
ORACLE1="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
ORACLE2="02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
ORACLE3="02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

ESCROW_AMOUNT="10000"   # 10,000 msat = 10 sats (plain integer → millisatoshi)
TIMEOUT_BLOCK="9999999" # far in the future

# ── Banner ─────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  E2E ESCROW HAPPY PATH TEST"
echo "  Flow: create → info → claim → verify balance"
echo "  Amount: ${ESCROW_AMOUNT} msat (10 sats)"
echo "════════════════════════════════════════════════════════"

# ── Step 1: Setup seller client ────────────────────────────────────────────────
info "Step 1: Set up seller client"

SELLER_DIR="$FM_CLIENT_BASE_DIR/seller-0"
mkdir -p "$SELLER_DIR"

# Get invite code (peer 0 since FM_FED_SIZE=1)
INVITE_CODE=$(buyer invite-code 0 | python3 -c "import sys,json; print(json.load(sys.stdin)['invite_code'])")
ok "Invite code: ${INVITE_CODE:0:30}..."

# Check if seller already joined (idempotent — client.db is a RocksDB directory)
if [[ -d "$SELLER_DIR/client.db" ]]; then
  ok "Seller already joined federation (skipping join)"
else
  seller join-federation "$INVITE_CODE" 2>&1 | grep -v "^$" | head -5 || true
  ok "Seller joined federation"
fi

# ── Step 2: Get seller public key ──────────────────────────────────────────────
info "Step 2: Get seller public key"
SELLER_PUBKEY=$(seller module escrow public-key | python3 -c "import sys,json; print(json.load(sys.stdin)['public_key'])")
ok "Seller pubkey: $SELLER_PUBKEY"

# ── Step 3: Record balances before ────────────────────────────────────────────
info "Step 3: Record balances before"
BUYER_BALANCE_BEFORE=$(buyer info | python3 -c "import sys,json; print(json.load(sys.stdin)['total_amount_msat'])")
SELLER_BALANCE_BEFORE=$(seller info | python3 -c "import sys,json; print(json.load(sys.stdin)['total_amount_msat'])")
ok "Buyer  balance: ${BUYER_BALANCE_BEFORE} msat"
ok "Seller balance: ${SELLER_BALANCE_BEFORE} msat"

# ── Step 4: Buyer creates escrow ───────────────────────────────────────────────
info "Step 4: Buyer creates escrow (${ESCROW_AMOUNT} msat)"

# Non-custodial design: buyer generates secret locally; only the SHA-256 hash
# is passed to the federation. The plaintext is used later to claim.
SECRET_CODE=$(python3 -c "import secrets; print(secrets.token_hex(32))")
SECRET_CODE_HASH=$(python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$SECRET_CODE")
ok "Secret code (local): ${SECRET_CODE:0:10}... (${#SECRET_CODE} chars)"
ok "Secret code hash:    ${SECRET_CODE_HASH:0:16}..."

CREATE_JSON=$(buyer module escrow create \
  "$SELLER_PUBKEY" \
  "$ORACLE1" "$ORACLE2" "$ORACLE3" \
  "$ESCROW_AMOUNT" "$TIMEOUT_BLOCK" \
  --secret-code-hash "$SECRET_CODE_HASH" 2>&1)

echo "    Raw output: $CREATE_JSON"

ESCROW_ID=$(echo "$CREATE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['escrow-id'])")
STATE_MSG=$(echo "$CREATE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")

ok "Escrow ID: $ESCROW_ID"
ok "State: $STATE_MSG"

# ── Step 5: Verify escrow is Open ─────────────────────────────────────────────
info "Step 5: Verify escrow state is Open"
INFO_JSON=$(buyer module escrow info "$ESCROW_ID" 2>&1)
echo "    Raw output: $INFO_JSON"

ESCROW_STATE=$(echo "$INFO_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")
ok "State: $ESCROW_STATE"
assert_eq "$ESCROW_STATE" "Open"

# ── Step 6: Seller claims with secret code ────────────────────────────────────
info "Step 6: Seller claims escrow"
CLAIM_JSON=$(seller module escrow claim "$ESCROW_ID" "$SECRET_CODE" 2>&1)
echo "    Raw output: $CLAIM_JSON"

CLAIM_STATUS=$(echo "$CLAIM_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
ok "Claim status: $CLAIM_STATUS"
assert_eq "$CLAIM_STATUS" "resolved"

# ── Step 7: Wait for balance to settle ────────────────────────────────────────
info "Step 7: Waiting for balance to settle..."
sleep 3

# ── Step 8: Verify seller received funds ──────────────────────────────────────
info "Step 8: Verify balances after"
BUYER_BALANCE_AFTER=$(buyer info | python3 -c "import sys,json; print(json.load(sys.stdin)['total_amount_msat'])")
SELLER_BALANCE_AFTER=$(seller info | python3 -c "import sys,json; print(json.load(sys.stdin)['total_amount_msat'])")

BUYER_DELTA=$(( BUYER_BALANCE_BEFORE - BUYER_BALANCE_AFTER ))
SELLER_DELTA=$(( SELLER_BALANCE_AFTER - SELLER_BALANCE_BEFORE ))

ok "Buyer  balance: ${BUYER_BALANCE_AFTER} msat  (Δ −${BUYER_DELTA} msat)"
ok "Seller balance: ${SELLER_BALANCE_AFTER} msat  (Δ +${SELLER_DELTA} msat)"

# Seller must have received something.
# Test federations charge mint fees on both sides, so we just verify > 0.
if (( SELLER_DELTA <= 0 )); then
  fail "Seller received nothing: +${SELLER_DELTA} msat"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo -e "  ${GREEN}✓ E2E HAPPY PATH TEST PASSED!${NC}"
echo "  Escrow ID:    $ESCROW_ID"
echo "  Amount:       ${ESCROW_AMOUNT} msat"
echo "  Seller got:   +${SELLER_DELTA} msat"
echo "  Buyer spent:  −${BUYER_DELTA} msat"
echo "════════════════════════════════════════════════════════"
