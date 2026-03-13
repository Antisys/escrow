#!/usr/bin/env bash
# E2E Dispute Flow Test — Fedimint Escrow Module
#
# Flow:
#   1. Buyer creates escrow with 3 oracle pubkeys (derived from known private keys)
#   2. Buyer disputes the escrow
#   3. State confirmed as DisputedByBuyer
#   4. Two oracle arbitrators sign attestations: "seller wins"
#   5. Seller submits oracle attestations → resolve-oracle
#   6. State confirmed as ResolvedByOracle
#   7. Seller balance increases
#
# Requires: active devimint federation (target/devimint symlink → live data dir)
#           secp256k1 Python library (pip install secp256k1)
# Usage: bash scripts/dev/e2e-dispute-flow.sh

set -euo pipefail

ESCROW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FEDIMINT_CLI="$ESCROW_DIR/target/debug/fedimint-cli"
ORACLE_SIGN="$ESCROW_DIR/tools/oracle_sign.py"
VENV="${PYTHON_VENV:-}"

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

# ── Activate venv for oracle_sign.py ──────────────────────────────────────────
# shellcheck disable=SC1090
source "$VENV"

# ── Client helpers ─────────────────────────────────────────────────────────────
buyer()  { "$FEDIMINT_CLI" --data-dir "$FM_CLIENT_DIR" "$@"; }
seller() { "$FEDIMINT_CLI" --data-dir "$FM_CLIENT_BASE_DIR/seller-0" "$@"; }

# ── Oracle private keys (32-byte hex) ─────────────────────────────────────────
# These are test keys — in production these would be the arbitrators' real keys.
ORACLE_PRIVKEY1="0101010101010101010101010101010101010101010101010101010101010101"
ORACLE_PRIVKEY2="0202020202020202020202020202020202020202020202020202020202020202"
ORACLE_PRIVKEY3="0303030303030303030303030303030303030303030303030303030303030303"

# Derive full compressed pubkeys from private keys
derive_pubkey() {
  python3 -c "
from secp256k1 import PrivateKey
k = PrivateKey(bytes.fromhex('$1'))
print(k.pubkey.serialize(compressed=True).hex())
"
}

ORACLE_PUBKEY1=$(derive_pubkey "$ORACLE_PRIVKEY1")
ORACLE_PUBKEY2=$(derive_pubkey "$ORACLE_PRIVKEY2")
ORACLE_PUBKEY3=$(derive_pubkey "$ORACLE_PRIVKEY3")

ESCROW_AMOUNT="10000"   # 10,000 msat = 10 sats
TIMEOUT_BLOCK="9999999"

# ── Banner ─────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  E2E ESCROW DISPUTE FLOW TEST"
echo "  Flow: create → dispute → oracle sign (2-of-3) → resolve → verify"
echo "  Outcome: seller wins"
echo "════════════════════════════════════════════════════════"
echo ""
echo "  Oracle pubkeys (compressed, 33 bytes):"
echo "    1: ${ORACLE_PUBKEY1:0:20}..."
echo "    2: ${ORACLE_PUBKEY2:0:20}..."
echo "    3: ${ORACLE_PUBKEY3:0:20}..."

# ── Step 1: Ensure seller has joined ──────────────────────────────────────────
info "Step 1: Ensure seller client is set up"
SELLER_DIR="$FM_CLIENT_BASE_DIR/seller-0"
if [[ -d "$SELLER_DIR/client.db" ]]; then
  ok "Seller already joined federation"
else
  mkdir -p "$SELLER_DIR"
  INVITE_CODE=$(buyer invite-code 0 | python3 -c "import sys,json; print(json.load(sys.stdin)['invite_code'])")
  seller join-federation "$INVITE_CODE" >/dev/null 2>&1
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

# ── Step 4: Buyer creates escrow with real oracle pubkeys ──────────────────────
info "Step 4: Buyer creates escrow (${ESCROW_AMOUNT} msat) with real oracle pubkeys"
# Non-custodial: generate secret locally; only hash goes to federation.
# Dispute path doesn't need the secret code (oracle resolves), but create requires a hash.
_SC=$(python3 -c "import secrets; print(secrets.token_hex(32))")
_SC_HASH=$(python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$_SC")
CREATE_JSON=$(buyer module escrow create \
  "$SELLER_PUBKEY" \
  "$ORACLE_PUBKEY1" "$ORACLE_PUBKEY2" "$ORACLE_PUBKEY3" \
  "$ESCROW_AMOUNT" "$TIMEOUT_BLOCK" \
  --secret-code-hash "$_SC_HASH" 2>&1)

echo "    Raw output: $CREATE_JSON"
ESCROW_ID=$(echo "$CREATE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['escrow-id'])")
ok "Escrow ID: $ESCROW_ID"

# ── Step 5: Verify state is Open ───────────────────────────────────────────────
info "Step 5: Verify escrow is Open"
STATE=$(buyer module escrow info "$ESCROW_ID" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")
ok "State: $STATE"
assert_eq "$STATE" "Open"

# ── Step 6: Buyer initiates dispute ───────────────────────────────────────────
info "Step 6: Buyer initiates dispute"
DISPUTE_JSON=$(buyer module escrow dispute "$ESCROW_ID" 2>&1)
echo "    Raw output: $DISPUTE_JSON"
DISPUTE_STATUS=$(echo "$DISPUTE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
ok "Dispute status: $DISPUTE_STATUS"
assert_eq "$DISPUTE_STATUS" "disputed!"

# ── Step 7: Verify state is DisputedByBuyer ───────────────────────────────────
info "Step 7: Verify escrow is now DisputedByBuyer"
STATE=$(buyer module escrow info "$ESCROW_ID" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")
ok "State: $STATE"
assert_eq "$STATE" "DisputedByBuyer"

# ── Step 8: Sign 2-of-3 oracle attestations (seller wins) ─────────────────────
info "Step 8: Two oracles sign attestation — outcome: seller wins"
DECIDED_AT=$(date +%s)

ATT1=$(python3 "$ORACLE_SIGN" \
  --privkey "$ORACLE_PRIVKEY1" \
  --escrow-id "$ESCROW_ID" \
  --outcome seller \
  --decided-at "$DECIDED_AT" \
  --reason "Seller provided proof of delivery")

ATT2=$(python3 "$ORACLE_SIGN" \
  --privkey "$ORACLE_PRIVKEY2" \
  --escrow-id "$ESCROW_ID" \
  --outcome seller \
  --decided-at "$DECIDED_AT" \
  --reason "Seller provided proof of delivery")

ok "Oracle 1 signed: pubkey ${ORACLE_PUBKEY1:0:16}..."
ok "Oracle 2 signed: pubkey ${ORACLE_PUBKEY2:0:16}..."

# Build JSON array of attestations
ATTESTATIONS_JSON=$(python3 -c "
import json, sys
att1 = $ATT1
att2 = $ATT2
print(json.dumps([att1, att2]))
")

echo "    Attestations JSON (truncated): ${ATTESTATIONS_JSON:0:120}..."

# ── Step 9: Seller submits oracle resolution (seller = winner, must use seller key) ──
info "Step 9: Seller submits oracle resolution"
RESOLVE_JSON=$(seller module escrow resolve-oracle "$ESCROW_ID" "$ATTESTATIONS_JSON" 2>&1)
echo "    Raw output: $RESOLVE_JSON"
RESOLVE_STATUS=$(echo "$RESOLVE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
ok "Resolve status: $RESOLVE_STATUS"
assert_eq "$RESOLVE_STATUS" "resolved via oracle"

# ── Step 10: Verify state is ResolvedByOracle ─────────────────────────────────
info "Step 10: Verify escrow state is ResolvedByOracle"
STATE=$(seller module escrow info "$ESCROW_ID" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")
ok "State: $STATE"
assert_eq "$STATE" "ResolvedByOracle"

# ── Step 11: Wait for balance to settle ───────────────────────────────────────
info "Step 11: Waiting for balance to settle..."
sleep 3

# ── Step 12: Verify seller received funds ─────────────────────────────────────
info "Step 12: Verify balances after"
BUYER_BALANCE_AFTER=$(buyer info | python3 -c "import sys,json; print(json.load(sys.stdin)['total_amount_msat'])")
SELLER_BALANCE_AFTER=$(seller info | python3 -c "import sys,json; print(json.load(sys.stdin)['total_amount_msat'])")

BUYER_DELTA=$(( BUYER_BALANCE_BEFORE - BUYER_BALANCE_AFTER ))
SELLER_DELTA=$(( SELLER_BALANCE_AFTER - SELLER_BALANCE_BEFORE ))

ok "Buyer  balance: ${BUYER_BALANCE_AFTER} msat  (Δ −${BUYER_DELTA} msat)"
ok "Seller balance: ${SELLER_BALANCE_AFTER} msat  (Δ +${SELLER_DELTA} msat)"

if (( SELLER_DELTA <= 0 )); then
  fail "Seller received nothing: +${SELLER_DELTA} msat"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo -e "  ${GREEN}✓ E2E DISPUTE FLOW TEST PASSED!${NC}"
echo "  Escrow ID:    $ESCROW_ID"
echo "  Amount:       ${ESCROW_AMOUNT} msat"
echo "  Oracle votes: oracles 1+2 → seller wins"
echo "  Seller got:   +${SELLER_DELTA} msat"
echo "  Buyer spent:  −${BUYER_DELTA} msat"
echo "════════════════════════════════════════════════════════"
