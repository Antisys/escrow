use fedimint_core::encoding::{Decodable, Encodable};
use secp256k1::schnorr::Signature;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

/// Nostr event kind used for escrow oracle attestations (parameterised replaceable)
pub const ORACLE_ATTESTATION_KIND: u32 = 30_001;

/// Who receives the escrow funds according to the oracle's decision
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub enum Beneficiary {
    Buyer,
    Seller,
}

impl std::fmt::Display for Beneficiary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Beneficiary::Buyer => write!(f, "buyer"),
            Beneficiary::Seller => write!(f, "seller"),
        }
    }
}

/// The content of a Nostr oracle attestation event
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct OracleAttestationContent {
    /// The escrow being resolved
    pub escrow_id: String,
    /// Who receives the funds
    pub outcome: Beneficiary,
    /// Unix timestamp of decision
    pub decided_at: u64,
    /// Human-readable reason (optional, for transparency)
    pub reason: Option<String>,
}

/// A single arbitrator's signed attestation
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct SignedAttestation {
    /// The arbitrator's secp256k1 pubkey (Nostr uses x-only internally)
    pub pubkey: PublicKey,
    /// BIP340 Schnorr signature over the canonical attestation bytes
    pub signature: Signature,
    /// The attested content
    pub content: OracleAttestationContent,
}

/// Compute the 32-byte message that an oracle signs for a given attestation.
///
/// Format mirrors Nostr event signing: SHA256 of a compact JSON array:
/// `[0, "<pubkey_hex>", <decided_at>, 30001, [["d","<escrow_id>"]], "<outcome>"]`
///
/// This is deterministic and reproducible in `tools/oracle_sign.py`.
pub fn attestation_signing_bytes(
    content: &OracleAttestationContent,
    pubkey: &PublicKey,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let (xonly, _parity) = pubkey.x_only_public_key();
    let pubkey_hex = hex::encode(xonly.serialize());

    // Compact JSON array matching Nostr event serialisation
    let msg = format!(
        "[0,\"{}\",{},{},[[\"d\",\"{}\"]],\"{}\"]",
        pubkey_hex,
        content.decided_at,
        ORACLE_ATTESTATION_KIND,
        content.escrow_id,
        content.outcome,
    );

    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    hasher.finalize().into()
}
