use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, Amount};
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

/// The structure for the database record
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct EscrowValue {
    pub buyer_pubkey: PublicKey,
    pub seller_pubkey: PublicKey,
    pub arbiter_pubkey: PublicKey,
    pub amount: Amount,
    pub secret_code_hash: String,
    pub max_arbiter_fee: Amount,
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
