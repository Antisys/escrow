# Escrow Module

A Fedimint custom module for trustless escrow between buyer and seller, with 2-of-3 Nostr oracle dispute resolution.

Based on [fedimint-custom-module-template](https://github.com/fedimint/fedimint-custom-modules-example).

**Version:** 0.3.0 (upgraded to Fedimint v0.11.0-alpha)

## Overview

This module facilitates secure transactions between a buyer and a seller. Funds are locked in a Fedimint escrow and can be released:
- **Cooperatively**: Seller claims with the secret code shared by the buyer
- **On timeout**: Automatically released to buyer (refund) or seller (release) per the configured timeout action
- **Via oracle dispute**: A 2-of-3 Nostr oracle quorum votes on the outcome

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

### 5. Oracle Attestation (via federation consensus)

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
graph TD
    A[Buyer] -->|Create Escrow + 3 Oracle Pubkeys| B[Escrow OPEN]
    B -->|Share SECRET_CODE off-band| C[Seller]
    C -->|No Dispute: Seller Claims| D[Escrow CLAIMED]
    B -->|Dispute raised by buyer or seller| E[Escrow DISPUTED]
    E -->|2-of-3 oracle Schnorr sigs agree| F[ResolvedByOracle]
    F -->|Winner claimed| G[Escrow RESOLVED]
    B -->|Block height > timeout_block| H[TimedOut → refund or release]
```

## Oracle Attestation Format

Oracles sign using BIP-340 Schnorr over SHA256 of:
```json
[0, "<pubkey_hex>", <decided_at_unix>, 30001, [["d", "<escrow_id>"]], "<buyer|seller>"]
```

This matches the Nostr NIP-01 event signing format for kind 30001 (parametrized replaceable events).

## Build

```bash
# Outside nix shell (requires system cargo ≥ 1.85)
cargo check -p fedimint-escrow-common -p fedimint-escrow-server -p fedimint-escrow-client

# Tests (17 unit tests)
cargo test -p fedimint-escrow-server
```

## Tests

17 unit tests covering:
- Escrow creation and storage
- Cooperative claim
- Timeout escape (block height gating, refund vs release action)
- Oracle 2-of-3 threshold: buyer wins, seller wins
- Oracle threshold failures: single sig, conflicting outcomes, unknown pubkey, wrong escrow_id, duplicate pubkey dedup
- Non-disputed state rejection

## Upgrade Notes

See [UPGRADE_NOTES.md](UPGRADE_NOTES.md) for the migration path from v0.3.0 (Fedimint v0.3.0) to v0.11.0-alpha.
