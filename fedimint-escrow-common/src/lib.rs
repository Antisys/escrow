pub mod endpoints;
pub mod oracle;

use std::fmt;

use config::EscrowClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{plugin_types_trait_impl_common, Amount};
use hex;
use oracle::SignedAttestation;
use secp256k1::schnorr::Signature;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

// Common contains types shared by both the client and server
pub mod config;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("escrow");

/// Modules are non-compatible with older versions
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(2, 0);

/// Non-transaction items that will be submitted to consensus.
/// Guardians propagate pending oracle attestations so all peers
/// can accumulate 2-of-3 before a client submits the input.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum EscrowConsensusItem {
    /// A single oracle attestation observed by this guardian
    OracleAttestation {
        escrow_id: String,
        attestation: SignedAttestation,
    },
    /// Current Bitcoin block count as seen by this guardian.
    /// Stored in BlockHeightKey so process_input can enforce timelocks.
    BlockHeight(u64),
}

impl std::fmt::Display for EscrowConsensusItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EscrowConsensusItem::OracleAttestation { escrow_id, .. } => {
                write!(f, "OracleAttestation(escrow_id={escrow_id})")
            }
            EscrowConsensusItem::BlockHeight(h) => {
                write!(f, "BlockHeight({h})")
            }
        }
    }
}

/// The states for the escrow module
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub enum EscrowStates {
    /// the escrow is created and not claimed by buyer or seller, thus its open
    Open,
    /// the escrow is resolved without dispute
    ResolvedWithoutDispute,
    /// the escrow is resolved with dispute
    ResolvedWithDispute,
    /// the escrow is disputed by buyer
    DisputedByBuyer,
    /// the escrow is disputed by seller
    DisputedBySeller,
    /// the escrow was claimed via timeout (timelock expired)
    TimedOut,
    /// the escrow was resolved by oracle attestation (2-of-3)
    ResolvedByOracle,
}

/// Determines who receives funds when the timeout elapses
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub enum TimeoutAction {
    /// Funds go to the seller (default: seller delivered, buyer unresponsive)
    Release,
    /// Funds go to the buyer (default: buyer paid, seller unresponsive)
    Refund,
}

/// The disputer in the escrow, can either be buyer or the seller
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Disputer {
    Buyer,
    Seller,
}

/// The input for the escrow module
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub enum EscrowInput {
    /// The input when seller is claiming the escrow without any dispute
    ClaimWithoutDispute(EscrowInputClaimWithoutDispute),
    /// The input when buyer or seller is disputing the escrow
    Disputing(EscrowInputDisputing),
    /// The input when 2-of-3 oracle signatures resolve the dispute
    OracleAttestation(EscrowInputOracleAttestation),
    /// The input when the authorized party claims after the timelock has expired
    TimeoutClaim(EscrowInputTimeoutClaim),
    /// Delegated claim: service submits, user's external signature authorizes (non-custodial)
    ClaimDelegated(EscrowInputClaimDelegated),
    /// Delegated timeout claim: service submits with user's pre-signed authorization
    TimeoutClaimDelegated(EscrowInputTimeoutClaimDelegated),
    /// Delegated dispute: service submits, user's signature proves identity
    DisputeDelegated(EscrowInputDisputeDelegated),
}
/// The input for the escrow module when the seller is claiming the escrow using
/// the secret code
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct EscrowInputClaimWithoutDispute {
    pub amount: Amount,
    pub escrow_id: String,
    pub secret_code: String,
    pub hashed_message: [u8; 32],
    pub signature: Signature,
}

/// The input for the escrow module when the buyer or seller is disputing the
/// escrow
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct EscrowInputDisputing {
    pub escrow_id: String,
    pub disputer: PublicKey,
    pub hashed_message: [u8; 32],
    pub signature: Signature,
}

/// The input for claiming the escrow after the timelock has expired
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct EscrowInputTimeoutClaim {
    pub amount: Amount,
    pub escrow_id: String,
    pub hashed_message: [u8; 32],
    pub signature: Signature,
}

/// The input for 2-of-3 oracle-attestation dispute resolution.
/// The submitter_pubkey (service) gets the e-cash via InputMeta for LN payout.
/// Authorization comes from the oracle attestations, not the transaction signer.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct EscrowInputOracleAttestation {
    pub amount: Amount,
    pub escrow_id: String,
    /// At least 2 valid, agreeing attestations from registered oracle pubkeys
    pub attestations: Vec<SignedAttestation>,
    /// The service's pubkey — receives e-cash for LN payout to winner
    pub submitter_pubkey: PublicKey,
}

/// Delegated claim: buyer proves consent (has secret + signs with their key).
/// The submitter_pubkey (service) gets the e-cash via InputMeta for LN payout.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct EscrowInputClaimDelegated {
    pub amount: Amount,
    pub escrow_id: String,
    pub secret_code: String,
    pub hashed_message: [u8; 32],
    /// Schnorr signature from buyer's ephemeral key over hashed_message
    pub external_signature: Signature,
    /// Service's pubkey — receives e-cash via InputMeta (framework auth)
    pub submitter_pubkey: PublicKey,
}

/// Delegated timeout claim: pre-signed by the authorized party (buyer for
/// refund, seller for release). Service submits with stored signature.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct EscrowInputTimeoutClaimDelegated {
    pub amount: Amount,
    pub escrow_id: String,
    pub hashed_message: [u8; 32],
    /// Schnorr signature from the authorized party's ephemeral key
    pub external_signature: Signature,
    /// Service's pubkey — receives e-cash via InputMeta (framework auth)
    pub submitter_pubkey: PublicKey,
}

/// Delegated dispute: user signs to prove identity, service submits.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct EscrowInputDisputeDelegated {
    pub escrow_id: String,
    /// The actual disputer's pubkey (must match buyer or seller in escrow)
    pub disputer: PublicKey,
    pub hashed_message: [u8; 32],
    /// Schnorr signature from the disputer's ephemeral key
    pub external_signature: Signature,
    /// Service's pubkey — for framework auth (zero-amount state change)
    pub submitter_pubkey: PublicKey,
}

/// The output for the escrow module
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct EscrowOutput {
    pub amount: Amount,
    pub buyer_pubkey: PublicKey,
    pub seller_pubkey: PublicKey,
    /// The 3 oracle (Nostr arbitrator) pubkeys; 2-of-3 needed for dispute resolution.
    /// Must contain exactly 3 elements (enforced in process_output).
    pub oracle_pubkeys: Vec<PublicKey>,
    pub escrow_id: String,
    pub secret_code_hash: String,
    /// Bitcoin block height after which the timeout escape path is available
    pub timeout_block: u32,
    /// Who receives funds when the timeout elapses
    pub timeout_action: TimeoutAction,
}

/// Errors that might be returned by the server when processing escrow inputs
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum EscrowInputError {
    #[error("Invalid secret code")]
    InvalidSecretCode,
    #[error("Invalid state for initiating dispute")]
    InvalidStateForInitiatingDispute,
    #[error("Invalid state for claiming escrow")]
    InvalidStateForClaimingEscrow,
    #[error("Unauthorized to dispute this escrow")]
    UnauthorizedToDispute,
    #[error("Timelock has not expired yet (current: {current}, required: {required})")]
    TimelockNotExpired { current: u64, required: u64 },
    #[error("Block height is unknown — cannot verify timelock")]
    BlockHeightUnknown,
    #[error("Invalid seller")]
    InvalidSeller,
    #[error("Invalid buyer")]
    InvalidBuyer,
    #[error("Escrow not found")]
    EscrowNotFound,
    #[error("Invalid public key")]
    InvalidPublicKey(String),
    // Oracle-specific errors
    #[error("Oracle threshold not met (need 2 agreeing signatures from registered oracles)")]
    OracleThresholdNotMet,
    #[error("Unknown oracle public key — not in registered oracle set")]
    UnknownOracle,
    #[error("Conflicting oracle outcomes (oracles disagree on beneficiary)")]
    ConflictingOracleOutcomes,
    #[error("Oracle attestation escrow_id does not match this escrow")]
    EscrowIdMismatch,
    #[error("Invalid oracle Schnorr signature")]
    InvalidOracleSignature,
}

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum EscrowOutputError {
    #[error("Escrow already exists")]
    EscrowAlreadyExists,
    #[error("Invalid oracle pubkey count (expected 3)")]
    InvalidOraclePubkeyCount,
}

/// The errors for the escrow module in client side
#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable, Serialize, Deserialize,
)]
pub enum EscrowError {
    #[error("Escrow is disputed and cannot be claimed")]
    EscrowDisputed,
    #[error("Transaction was rejected")]
    TransactionRejected,
    #[error("Escrow not found")]
    EscrowNotFound,
}

impl From<secp256k1::Error> for EscrowInputError {
    fn from(error: secp256k1::Error) -> Self {
        EscrowInputError::InvalidPublicKey(error.to_string())
    }
}

/// Contains the types defined above
#[derive(Debug, Clone)]
pub struct EscrowModuleTypes;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EscrowOutputOutcome {}

impl std::fmt::Display for EscrowOutputOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EscrowOutputOutcome")
    }
}

// Wire together the types for this module
// Note: KIND is now required as the first argument (changed in v0.4+)
plugin_types_trait_impl_common!(
    KIND,
    EscrowModuleTypes,
    EscrowClientConfig,
    EscrowInput,
    EscrowOutput,
    EscrowOutputOutcome,
    EscrowConsensusItem,
    EscrowInputError,
    EscrowOutputError
);

/// The common initializer for the escrow module
#[derive(Debug)]
pub struct EscrowCommonInit;

impl CommonModuleInit for EscrowCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = EscrowClientConfig;

    fn decoder() -> Decoder {
        EscrowModuleTypes::decoder_builder().build()
    }
}

impl fmt::Display for EscrowClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EscrowClientConfig {{ deposit_fee: {} }}",
            self.deposit_fee
        )
    }
}

impl fmt::Display for EscrowInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EscrowInput::ClaimWithoutDispute(input) => write!(
                f,
                "EscrowInput::ClaimWithoutDispute {{ amount: {}, escrow_id: {} }}",
                input.amount, input.escrow_id
            ),
            EscrowInput::Disputing(input) => write!(
                f,
                "EscrowInput::Disputing {{ disputer: {:?} }}",
                input.disputer
            ),
            EscrowInput::OracleAttestation(input) => write!(
                f,
                "EscrowInput::OracleAttestation {{ escrow_id: {}, num_attestations: {} }}",
                input.escrow_id,
                input.attestations.len()
            ),
            EscrowInput::TimeoutClaim(input) => write!(
                f,
                "EscrowInput::TimeoutClaim {{ amount: {}, escrow_id: {} }}",
                input.amount, input.escrow_id
            ),
            EscrowInput::ClaimDelegated(input) => write!(
                f,
                "EscrowInput::ClaimDelegated {{ amount: {}, escrow_id: {} }}",
                input.amount, input.escrow_id
            ),
            EscrowInput::TimeoutClaimDelegated(input) => write!(
                f,
                "EscrowInput::TimeoutClaimDelegated {{ amount: {}, escrow_id: {} }}",
                input.amount, input.escrow_id
            ),
            EscrowInput::DisputeDelegated(input) => write!(
                f,
                "EscrowInput::DisputeDelegated {{ escrow_id: {}, disputer: {:?} }}",
                input.escrow_id, input.disputer
            ),
        }
    }
}

impl fmt::Display for EscrowOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EscrowOutput {{ amount: {}, buyer_pubkey: {:?}, seller_pubkey: {:?}, oracle_pubkeys: {:?}, escrow_id: {}, secret_code_hash: {}, timeout_block: {}, timeout_action: {:?} }}",
            self.amount,
            self.buyer_pubkey,
            self.seller_pubkey,
            self.oracle_pubkeys,
            self.escrow_id,
            self.secret_code_hash,
            self.timeout_block,
            self.timeout_action
        )
    }
}

/// Hashes the value using SHA256
pub fn hash256(value: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
