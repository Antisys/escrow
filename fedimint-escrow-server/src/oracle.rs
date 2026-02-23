use fedimint_escrow_common::oracle::{attestation_signing_bytes, Beneficiary, SignedAttestation};
use secp256k1::{Message, PublicKey, Secp256k1};

/// Errors returned by oracle verification
#[derive(Debug, thiserror::Error)]
pub enum OracleVerifyError {
    #[error("Invalid oracle Schnorr signature")]
    InvalidSignature,
    #[error("Unknown oracle public key — not in registered oracle set")]
    UnknownOracle,
    #[error("Oracle attestation escrow_id does not match this escrow")]
    EscrowIdMismatch,
    #[error("Conflicting oracle outcomes (oracles disagree on beneficiary)")]
    ConflictingOutcomes,
    #[error("Oracle threshold not met (got {got}, need {need})")]
    ThresholdNotMet { got: usize, need: usize },
}

/// Verify a single SignedAttestation against the registered oracle pubkeys.
/// Checks:
///   1. The attestation's pubkey is one of the 3 registered oracles.
///   2. The content escrow_id matches expected_escrow_id.
///   3. The Schnorr signature is valid over the canonical signing bytes.
pub fn verify_attestation(
    attestation: &SignedAttestation,
    oracle_pubkeys: &[PublicKey],
    expected_escrow_id: &str,
) -> Result<(), OracleVerifyError> {
    // 1. Pubkey must be in the registered set
    if !oracle_pubkeys.contains(&attestation.pubkey) {
        return Err(OracleVerifyError::UnknownOracle);
    }

    // 2. escrow_id must match
    if attestation.content.escrow_id != expected_escrow_id {
        return Err(OracleVerifyError::EscrowIdMismatch);
    }

    // 3. Verify Schnorr signature
    let msg_bytes = attestation_signing_bytes(&attestation.content, &attestation.pubkey);
    let secp = Secp256k1::new();
    let message = Message::from_digest_slice(&msg_bytes).expect("32 bytes");
    let (xonly, _parity) = attestation.pubkey.x_only_public_key();
    secp.verify_schnorr(&attestation.signature, &message, &xonly)
        .map_err(|_| OracleVerifyError::InvalidSignature)
}

/// Verify that at least 2 attestations agree on the same outcome (2-of-3 threshold).
///
/// Rules:
/// - Each individual attestation must pass `verify_attestation`.
/// - Each oracle pubkey is counted at most once (deduplication).
/// - All valid votes must agree on a single outcome; conflicting outcomes are rejected.
/// - At least 2 distinct oracle signatures must agree.
///
/// Returns the winning `Beneficiary` if the threshold is met.
pub fn verify_threshold(
    attestations: &[SignedAttestation],
    oracle_pubkeys: &[PublicKey],
    escrow_id: &str,
) -> Result<Beneficiary, OracleVerifyError> {
    let mut seen_pubkeys = std::collections::HashSet::new();
    let mut buyer_count: usize = 0;
    let mut seller_count: usize = 0;

    for attestation in attestations {
        // Each attestation must be individually valid
        verify_attestation(attestation, oracle_pubkeys, escrow_id)?;

        // Each oracle pubkey counts at most once
        if seen_pubkeys.contains(&attestation.pubkey) {
            continue;
        }
        seen_pubkeys.insert(attestation.pubkey);

        match attestation.content.outcome {
            Beneficiary::Buyer => buyer_count += 1,
            Beneficiary::Seller => seller_count += 1,
        }
    }

    // Conflicting outcomes: votes on both sides
    if buyer_count > 0 && seller_count > 0 {
        return Err(OracleVerifyError::ConflictingOutcomes);
    }

    let total = buyer_count + seller_count;
    if total < 2 {
        return Err(OracleVerifyError::ThresholdNotMet { got: total, need: 2 });
    }

    if buyer_count >= 2 {
        Ok(Beneficiary::Buyer)
    } else {
        Ok(Beneficiary::Seller)
    }
}
