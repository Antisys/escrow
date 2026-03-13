#!/usr/bin/env bash
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
      --exec bash scripts/dev/e2e-happy-path.sh
  "
