#!/usr/bin/env bash
# Launch devimint with mprocs monitoring UI
# This requires an interactive terminal.

set -euo pipefail

ESCROW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "=== Checking required binaries ==="
MISSING=0
# Check both target/debug (non-nix builds) and target-nix/debug (nix devshell builds)
for binary in devimint fedimintd fedimint-cli gatewayd gateway-cli fedimint-recurringd fedimint-recurringdv2; do
  if [ -f "$ESCROW_DIR/target-nix/debug/$binary" ] || [ -f "$ESCROW_DIR/target/debug/$binary" ]; then
    echo "✅ $binary"
  else
    echo "❌ MISSING: $binary"
    MISSING=1
  fi
done

if [ "$MISSING" -eq 1 ]; then
  echo ""
  echo "ERROR: Some binaries are missing. They should already be built."
  echo "If they're gone, re-run the build from the previous session context."
  exit 1
fi

echo ""
echo "=== Launching devimint dev-fed with mprocs ==="
echo "  Federation size: 1 guardian (FM_FED_SIZE=1)"
echo "  Press Ctrl+a then q to quit mprocs"
echo ""

cd "$ESCROW_DIR"

exec env FM_FED_SIZE=1 SKIP_CARGO_BUILD=1 \
  PATH="/nix/var/nix/profiles/default/bin:$PATH" \
  nix develop "${FEDIMINT_DIR:-$ESCROW_DIR/../fedimint}" --command bash -c "
    export PATH=\"$ESCROW_DIR/target-nix/debug:$ESCROW_DIR/target/debug:\$PATH\" && \
    FM_FED_SIZE=1 SKIP_CARGO_BUILD=1 \
    devimint --link-test-dir ./target/devimint dev-fed \
      --exec bash -c 'mprocs -c misc/mprocs.yaml 2>\$FM_LOGS_DIR/devimint-outer.log'
  "
