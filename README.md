# Fedimint Escrow Module

A Fedimint custom module for trustless escrow between buyer and seller, with 2-of-3 Nostr oracle dispute resolution.

Based on [fedimint-custom-modules-example](https://github.com/fedimint/fedimint-custom-modules-example).

## Overview

This module facilitates secure transactions between a buyer and a seller. Funds are locked in a Fedimint escrow and can be released:
- **Cooperatively**: Seller claims with the secret code shared by the buyer
- **On timeout**: Automatically released to buyer (refund) or seller (release) per the configured timeout action
- **Via oracle dispute**: A 2-of-3 Nostr oracle quorum votes on the outcome

## Crates

| Crate | Description |
|-------|-------------|
| `fedimint-escrow-common` | Shared types, error definitions, oracle attestation format |
| `fedimint-escrow-server` | Guardian-side consensus logic (state machine, validation) |
| `fedimint-escrow-client` | Client-side operations (create, claim, dispute, resolve) |
| `fedimint-cli-custom` | Custom fedimint-cli binary with escrow module included |
| `fedimintd-custom` | Custom fedimintd binary with escrow module included |
| `escrow-httpd` | Persistent HTTP daemon — eliminates ~13s cold-start per CLI invocation |

## Architecture

### Roles
- **Buyer**: Creates the escrow, locks ecash, holds the secret code
- **Seller**: Claims ecash by presenting the valid secret code
- **Oracle set**: 3 registered Nostr pubkeys; 2-of-3 Schnorr signatures needed to resolve disputes

### States
```
Open → Claimed (cooperative, seller presents secret code)
Open → DisputedByBuyer / DisputedBySeller
     → ResolvedByOracle (2-of-3 oracle quorum decides)
Open → TimedOut (block height exceeded, funds go to configured beneficiary)
```

## Prerequisites

This module builds against Fedimint v0.11.0-alpha (unreleased). You need the fedimint source tree as a sibling directory:

```bash
git clone https://github.com/fedimint/fedimint.git
git clone <this-repo> fedimint-escrow
# Directory layout:
#   fedimint/
#   fedimint-escrow/
```

## Build

```bash
# Module crates (requires system cargo >= 1.85)
cargo check -p fedimint-escrow-common -p fedimint-escrow-server -p fedimint-escrow-client

# Custom fedimintd (requires nix devshell for fedimint dependencies)
nix develop ../fedimint --command bash -c \
  "CARGO_TARGET_DIR=target-nix cargo build --release -p fedimintd-custom"

# escrow-httpd (persistent HTTP daemon)
nix develop ../fedimint --command bash -c \
  "CARGO_TARGET_DIR=target-nix cargo build --release -p escrow-httpd"

# Tests (17 unit tests)
cargo test -p fedimint-escrow-server
```

## escrow-httpd

Persistent HTTP daemon that keeps a Fedimint client alive and exposes REST endpoints. Eliminates the ~13s cold-start overhead of spawning `fedimint-cli` per request.

### Usage

```bash
escrow-httpd --data-dir /path/to/client-data --bind 127.0.0.1:5400
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/info` | Wallet balance |
| GET | `/escrow/public-key` | Service public key |
| GET | `/escrow/{id}/info` | Escrow state and details |
| GET | `/block-height` | Federation consensus block height |
| POST | `/escrow/receive-into-escrow` | Create BOLT11 invoice + pre-register escrow |
| POST | `/escrow/await-receive` | Poll for invoice payment |
| POST | `/escrow/await-invoice` | Poll LN invoice status |
| POST | `/escrow/claim-and-pay` | Claim with secret code + pay via LN |
| POST | `/escrow/claim-timeout-and-pay` | Claim after timeout + pay via LN |
| POST | `/escrow/claim-delegated-and-pay` | Delegated claim (user-signed) + pay via LN |
| POST | `/escrow/claim-timeout-delegated-and-pay` | Delegated timeout claim + pay via LN |
| POST | `/escrow/dispute-delegated` | Delegated dispute initiation |
| POST | `/escrow/resolve-oracle` | Resolve via oracle attestations |
| POST | `/escrow/resolve-oracle-and-pay` | Resolve via oracle + pay via LN |

All fund-moving operations go through escrow authorization (secret code, oracle signatures, or timelock). There is no standalone payment endpoint.

## CLI Commands

### 1. Create Escrow

```
fedimint-cli module escrow create \
  [SELLER_PUBKEY] \
  [ORACLE_PUBKEY1] [ORACLE_PUBKEY2] [ORACLE_PUBKEY3] \
  [COST_MSAT] \
  [TIMEOUT_BLOCK] \
  [timeout_action: "refund" (default) | "release"]
```

Creates an escrow. Returns:
- `secret-code`: Share with seller off-band for cooperative claim
- `escrow-id`: Unique identifier for the escrow
- `state`: `"escrow opened!"`

*Buyer only.*

### 2. Get Escrow Info

```
fedimint-cli module escrow info [ESCROW_ID]
```

Returns all escrow fields including oracle pubkeys, state, timeout settings.

### 3. Claim Escrow

```
fedimint-cli module escrow claim [ESCROW_ID] [SECRET_CODE]
```

Seller claims by presenting the secret code. Only valid in `Open` state.

*Seller only.*

### 4. Initiate Dispute

```
fedimint-cli module escrow dispute [ESCROW_ID]
```

Either party can raise a dispute. Transitions to `DisputedByBuyer` or `DisputedBySeller`.

### 5. Oracle Attestation

Oracles submit signed attestations off-chain. Guardians accumulate them via consensus items. Once 2-of-3 oracles agree, the winner can submit `OracleAttestation` input to claim funds.

**Signing tool:**
```bash
python tools/oracle_sign.py \
  --privkey <hex_privkey> \
  --escrow-id <id> \
  --outcome buyer|seller \
  --decided-at <unix_ts> \
  --reason "Goods delivered"
```

### 6. Get Public Key

```
fedimint-cli module escrow public-key
```

Returns the client's public key for use in escrow creation.

## Dispute Resolution Flow

```
Buyer creates escrow with 3 oracle pubkeys
  → Escrow OPEN
  → Seller claims with secret code → CLAIMED
  → Either party disputes → DISPUTED
    → 2-of-3 oracle Schnorr sigs agree → RESOLVED
  → Block height > timeout_block → TIMED_OUT (refund or release)
```

## Oracle Attestation Format

Oracles sign using BIP-340 Schnorr over SHA256 of:
```json
[0, "<pubkey_hex>", <decided_at_unix>, 30001, [["d", "<escrow_id>"]], "<buyer|seller>"]
```

This matches the Nostr NIP-01 event signing format for kind 30001 (parametrized replaceable events).

## Tests

17 unit tests covering:
- Escrow creation and storage
- Cooperative claim
- Timeout escape (block height gating, refund vs release action)
- Oracle 2-of-3 threshold: buyer wins, seller wins
- Oracle threshold failures: single sig, conflicting outcomes, unknown pubkey, wrong escrow_id, duplicate pubkey dedup
- Non-disputed state rejection

## License

MIT — see [LICENSE](LICENSE).
