use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, Amount};
use fedimint_escrow_common::oracle::SignedAttestation;
use fedimint_escrow_common::{EscrowStates, TimeoutAction};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

/// Namespaces DB keys for this module
#[repr(u8)]
#[derive(Clone, Debug, EnumIter)]
pub enum DbKeyPrefix {
    Escrow = 0x04,
    /// Stores the last known Bitcoin block height for timelock checks
    BlockHeight = 0x05,
    /// Stores pending oracle attestations accumulated via consensus
    PendingOracleAttestation = 0x06,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The key structure using a random escrow_id
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct EscrowKey {
    pub escrow_id: String,
}

/// Prefix for scanning all escrows (used by audit)
#[derive(Debug, Encodable, Decodable)]
pub struct EscrowKeyPrefix;

/// Key for the consensus block height used in timelock checks
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct BlockHeightKey;

/// Key for a single pending oracle attestation (per escrow, per oracle pubkey)
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct PendingOracleAttestationKey {
    pub escrow_id: String,
    pub pubkey: PublicKey,
}

/// Prefix for scanning all pending attestations for a given escrow
#[derive(Debug, Encodable, Decodable)]
pub struct PendingOracleAttestationKeyPrefix {
    pub escrow_id: String,
}

/// Prefix for scanning ALL pending attestations (used by consensus_proposal)
#[derive(Debug, Encodable, Decodable)]
pub struct AllPendingOracleAttestationsPrefix;

/// The structure for the database record
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct EscrowValue {
    pub buyer_pubkey: PublicKey,
    pub seller_pubkey: PublicKey,
    /// The 3 oracle (Nostr arbitrator) pubkeys; 2-of-3 needed for dispute resolution
    pub oracle_pubkeys: Vec<PublicKey>,
    pub amount: Amount,
    pub secret_code_hash: String,
    pub state: EscrowStates,
    /// Block height after which the timeout escape path is available
    pub timeout_block: u32,
    /// Who receives funds when the timeout elapses
    pub timeout_action: TimeoutAction,
}

impl_db_record!(
    key = EscrowKey,
    value = EscrowValue,
    db_prefix = DbKeyPrefix::Escrow,
);

impl_db_lookup!(
    key = EscrowKey,
    query_prefix = EscrowKeyPrefix
);

impl_db_record!(
    key = BlockHeightKey,
    value = u64,
    db_prefix = DbKeyPrefix::BlockHeight,
);

impl_db_record!(
    key = PendingOracleAttestationKey,
    value = SignedAttestation,
    db_prefix = DbKeyPrefix::PendingOracleAttestation,
);

impl_db_lookup!(
    key = PendingOracleAttestationKey,
    query_prefix = PendingOracleAttestationKeyPrefix
);

impl_db_lookup!(
    key = PendingOracleAttestationKey,
    query_prefix = AllPendingOracleAttestationsPrefix
);
