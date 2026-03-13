#!/usr/bin/env bash
# Run all three E2E tests in a single devimint session.
# Usage: bash scripts/dev/run-all-e2e.sh
set -euo pipefail

ESCROW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FEDIMINT_DIR="${FEDIMINT_DIR:-$ESCROW_DIR/../fedimint}"
cd "$ESCROW_DIR"

exec env FM_FED_SIZE=1 SKIP_CARGO_BUILD=1 \
  PATH="/nix/var/nix/profiles/default/bin:$PATH" \
  nix develop "$FEDIMINT_DIR" --command bash -c "
    export PATH=\"$ESCROW_DIR/target/debug:\$PATH\" && \
    FM_FED_SIZE=1 SKIP_CARGO_BUILD=1 \
    devimint --link-test-dir ./target/devimint dev-fed \
      --exec bash -c '
        bash scripts/dev/e2e-happy-path.sh &&
        bash scripts/dev/e2e-timeout-path.sh &&
        bash scripts/dev/e2e-dispute-flow.sh
      '
  "
