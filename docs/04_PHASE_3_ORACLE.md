# Phase 3: Nostr Oracle Integration

**Goal:** 2-of-3 Nostr arbitrator signatures can unlock escrow funds.
**Prerequisite:** Phase 2 complete (cooperative and timeout paths work)
**Estimated effort:** 1 week

---

## Context for Claude

This phase implements the dispute resolution path. When buyer and seller cannot agree, 3 independent arbitrators (identified by Nostr pubkeys) review evidence and sign an outcome. 2-of-3 signatures are required to release funds to the winning party.

**Nostr basics for this implementation:**
- A Nostr identity is a secp256k1 keypair (same curve as Bitcoin)
- A Nostr event is a JSON object with: `id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig`
- The `sig` field is a Schnorr signature over `sha256(serialised_event)`
- Nostr uses Schnorr signatures (not ECDSA) — use the `nostr` or `secp256k1` crate with Schnorr support

The oracle event format used in this project is a **custom Nostr kind** (30_000+ range for parameterised replaceable events). The event encodes the escrow outcome.

---

## Tasks

### Task 3.1 — Define oracle event format

In `fedimint-escrow-common/src/oracle.rs`:

```rust
/// The Nostr event kind used for escrow oracle attestations
pub const ORACLE_ATTESTATION_KIND: u32 = 30_001;

/// The content of a Nostr oracle attestation event
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct OracleAttestationContent {
    /// The escrow being resolved
    pub escrow_id: EscrowId,
    /// Who receives the funds
    pub outcome: Beneficiary,   // Buyer or Seller
    /// Unix timestamp of decision
    pub decided_at: u64,
    /// SHA256 of the evidence bundle reviewed
    pub evidence_hash: sha256::Hash,
    /// Human-readable reason (optional, for transparency)
    pub reason: Option<String>,
}

/// A single arbitrator's signed attestation
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SignedAttestation {
    /// The arbitrator's Nostr pubkey (secp256k1)
    pub pubkey: nostr::PublicKey,
    /// The Nostr event id (sha256 of serialised event)
    pub event_id: sha256::Hash,
    /// Schnorr signature
    pub signature: nostr::Signature,
    /// The attested content
    pub content: OracleAttestationContent,
}
```

---

### Task 3.2 — Implement signature verification

In `fedimint-escrow-server/src/oracle.rs`:

```rust
use nostr::{Event, PublicKey};

/// Verify a single arbitrator's Nostr signature
pub fn verify_attestation(
    attestation: &SignedAttestation,
    expected_escrow_id: &EscrowId,
    expected_oracle_pubkeys: &[secp256k1::PublicKey; 3],
) -> Result<(), OracleVerifyError> {

    // 1. Check pubkey is one of the 3 registered oracle keys
    let is_registered = expected_oracle_pubkeys
        .iter()
        .any(|k| k == &attestation.pubkey.into());
    if !is_registered {
        return Err(OracleVerifyError::UnknownArbitrator);
    }

    // 2. Verify Schnorr signature over the event
    let event_bytes = serialise_oracle_event(&attestation.content);
    let event_hash = sha256::Hash::hash(&event_bytes);
    attestation.pubkey.verify(
        &event_hash.into_32(),
        &attestation.signature,
    ).map_err(|_| OracleVerifyError::InvalidSignature)?;

    // 3. Check escrow_id matches
    if attestation.content.escrow_id != *expected_escrow_id {
        return Err(OracleVerifyError::EscrowIdMismatch);
    }

    Ok(())
}

/// Verify that we have >= 2 valid, agreeing signatures
pub fn verify_threshold(
    attestations: &[SignedAttestation],
    escrow_id: &EscrowId,
    oracle_pubkeys: &[secp256k1::PublicKey; 3],
) -> Result<Beneficiary, OracleVerifyError> {

    let mut valid: Vec<&SignedAttestation> = vec![];

    for att in attestations {
        if verify_attestation(att, escrow_id, oracle_pubkeys).is_ok() {
            valid.push(att);
        }
    }

    if valid.len() < 2 {
        return Err(OracleVerifyError::InsufficientSignatures {
            got: valid.len(),
            required: 2,
        });
    }

    // All valid signatures must agree on the same outcome
    let outcome = valid[0].content.outcome;
    for att in &valid[1..] {
        if att.content.outcome != outcome {
            return Err(OracleVerifyError::ConflictingOutcomes);
        }
    }

    Ok(outcome)
}
```

---

### Task 3.3 — Implement OracleAttestation input path

Back in `process_input`, replace the `todo!()`:

```rust
EscrowInput::OracleAttestation { escrow_id, attestations } => {
    let contract = self.get_contract(dbtx, escrow_id).await?;

    // Verify 2-of-3 oracle signatures
    let outcome = verify_threshold(
        attestations,
        escrow_id,
        &contract.oracle_pubkeys,
    )?;

    // Verify all attestations agree on outcome (done inside verify_threshold)
    // Finalize the escrow
    self.finalize_escrow(dbtx, escrow_id, contract.amount).await?;

    // Record which beneficiary won (for client to know who to pay)
    dbtx.insert_entry(
        &EscrowOutcomeKey(*escrow_id),
        &outcome,
    ).await;

    Ok(InputMeta { amount: contract.amount, .. })
}
```

---

### Task 3.4 — Implement consensus propagation

Guardians need to share oracle attestations with each other (one guardian may receive the attestation before others).

```rust
async fn consensus_proposal(
    &self,
    dbtx: &mut DatabaseTransaction<'_>,
) -> Vec<EscrowConsensusItem> {
    // Find any pending oracle attestations not yet confirmed by consensus
    let pending = dbtx.find_by_prefix(&PendingOracleAttestationPrefix).await;
    pending.map(|(_, item)| EscrowConsensusItem::OracleAttestation(item)).collect()
}

async fn process_consensus_item(
    &self,
    dbtx: &mut DatabaseTransaction<'_>,
    item: EscrowConsensusItem,
) -> Result<(), ConsensusItemError> {
    match item {
        EscrowConsensusItem::OracleAttestation { escrow_id, attestations } => {
            // Validate and store as confirmed
            let contract = self.get_contract(dbtx, &escrow_id).await?;
            verify_threshold(&attestations, &escrow_id, &contract.oracle_pubkeys)?;

            dbtx.insert_entry(
                &ConfirmedOracleAttestationKey(escrow_id),
                &attestations,
            ).await;

            // Remove from pending
            dbtx.remove_entry(&PendingOracleAttestationKey(escrow_id)).await;

            Ok(())
        }
    }
}
```

---

### Task 3.5 — Oracle CLI tool (for testing)

Create a simple tool to simulate an arbitrator signing an outcome.
This is used during development when you ARE the arbitrator.

In `/home/ralf/ln-escrow/tools/oracle_sign.py`:

```python
#!/usr/bin/env python3
"""
Simulate a Nostr oracle arbitrator signing an escrow outcome.
Used for testing — in production, arbitrators run their own tool.

Usage:
  python oracle_sign.py --key <nostr_nsec> --escrow <escrow_id> --outcome seller
"""
import sys, json, hashlib, time
from nostr.key import PrivateKey

def sign_outcome(nsec: str, escrow_id: str, outcome: str, reason: str = ""):
    private_key = PrivateKey.from_nsec(nsec)
    content = {
        "escrow_id": escrow_id,
        "outcome": outcome,
        "decided_at": int(time.time()),
        "reason": reason,
    }
    event = private_key.sign_event({
        "kind": 30001,
        "content": json.dumps(content),
        "tags": [["d", escrow_id]],
        "created_at": int(time.time()),
    })
    print(json.dumps(event, indent=2))
```

---

### Task 3.6 — Unit tests

```rust
#[test]
fn test_single_valid_signature() {
    // Sign with oracle key 1 → verify passes for single sig
    // But verify_threshold should fail (needs 2)
}

#[test]
fn test_two_valid_signatures_same_outcome() {
    // Sign with keys 1 and 2, same outcome → verify_threshold passes
}

#[test]
fn test_conflicting_outcomes_rejected() {
    // Key 1 signs "release", key 2 signs "refund" → ConflictingOutcomes error
}

#[test]
fn test_unknown_arbitrator_rejected() {
    // Sign with a key not in oracle_pubkeys → UnknownArbitrator error
}

#[test]
fn test_wrong_escrow_id_rejected() {
    // Sign with correct key but wrong escrow_id → EscrowIdMismatch error
}
```

---

## Definition of Done

- [ ] `OracleAttestationContent` and `SignedAttestation` types defined
- [ ] `verify_attestation()` validates Schnorr signature and pubkey membership
- [ ] `verify_threshold()` requires 2-of-3 agreeing signatures
- [ ] `OracleAttestation` input path implemented in `process_input`
- [ ] `consensus_proposal` and `process_consensus_item` propagate attestations
- [ ] `oracle_sign.py` tool works for simulating arbitrators
- [ ] All oracle unit tests pass
- [ ] `cargo test` passes (all phases)

---

## Notes on Nostr Schnorr vs secp256k1 ECDSA

Nostr uses **Schnorr signatures** (BIP340), not ECDSA. Fedimint's existing code uses ECDSA for Bitcoin operations. These are different signature schemes on the same curve.

Use the `nostr` crate (Rust) for Nostr event verification — it handles the correct BIP340 Schnorr verification. Do NOT use `secp256k1::ecdsa` for oracle signatures.

```toml
# In Cargo.toml
nostr = "0.34"  # check for latest version
```

---

*Next: See 05_PHASE_4_CLIENT.md*
