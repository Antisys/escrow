mod db;
mod oracle;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use anyhow::bail;
use async_trait::async_trait;
pub use db::EscrowValue;
use db::{
    AllPendingOracleAttestationsPrefix, BlockHeightKey, DbKeyPrefix, EscrowKey, EscrowKeyPrefix,
    PendingOracleAttestationKey,
};
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped, NonCommittable,
};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiError, ApiVersion, Amounts, CORE_CONSENSUS_VERSION,
    CoreConsensusVersion, InputMeta, ModuleConsensusVersion, ModuleInit,
    SupportedModuleApiVersions, TransactionItemAmounts,
};
use fedimint_core::{push_db_pair_items, Amount, InPoint, OutPoint, PeerId};
use fedimint_escrow_common::config::{
    EscrowClientConfig, EscrowConfig, EscrowConfigConsensus, EscrowConfigPrivate,
};
use fedimint_escrow_common::endpoints::{EscrowInfo, GET_MODULE_INFO};
use fedimint_escrow_common::oracle::Beneficiary;
use fedimint_escrow_common::{
    hash256, Disputer, EscrowCommonInit, EscrowConsensusItem, EscrowInput, EscrowInputError,
    EscrowModuleTypes, EscrowOutput, EscrowOutputError, EscrowOutputOutcome, EscrowStates,
    TimeoutAction, MODULE_CONSENSUS_VERSION,
};
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use futures::StreamExt;
use secp256k1::{Message, Secp256k1};
use strum::IntoEnumIterator;

/// Generates the module
#[derive(Debug, Clone)]
pub struct EscrowInit;

// Note: ModuleInit does NOT use #[async_trait] in v0.4+ (uses AFIT instead)
impl ModuleInit for EscrowInit {
    type Common = EscrowCommonInit;

    /// Dumps all database items for debugging
    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for prefix in filtered_prefixes {
            match prefix {
                DbKeyPrefix::Escrow => {
                    push_db_pair_items!(
                        dbtx,
                        EscrowKeyPrefix,
                        EscrowKey,
                        EscrowValue,
                        items,
                        "Escrow"
                    );
                }
                DbKeyPrefix::BlockHeight => {
                    // Singleton key — nothing to enumerate
                }
                DbKeyPrefix::PendingOracleAttestation => {
                    push_db_pair_items!(
                        dbtx,
                        AllPendingOracleAttestationsPrefix,
                        PendingOracleAttestationKey,
                        fedimint_escrow_common::oracle::SignedAttestation,
                        items,
                        "PendingOracleAttestation"
                    );
                }
            }
        }
        Box::new(items.into_iter())
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for EscrowInit {
    type Module = Escrow;

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(
            (CORE_CONSENSUS_VERSION.major, CORE_CONSENSUS_VERSION.minor),
            (
                MODULE_CONSENSUS_VERSION.major,
                MODULE_CONSENSUS_VERSION.minor,
            ),
            &[(0, 0)],
        )
    }

    /// Initialize the module
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(Escrow::new(args.cfg().to_typed()?))
    }

    /// Generates configs for all peers in a trusted manner for testing
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        _args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        peers
            .iter()
            .map(|&peer| {
                let config = EscrowConfig {
                    private: EscrowConfigPrivate,
                    consensus: EscrowConfigConsensus {
                        deposit_fee: Amount::ZERO,
                    },
                };
                (peer, config.to_erased())
            })
            .collect()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        _peers: &(dyn PeerHandleOps + Send + Sync),
        _args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        Ok(EscrowConfig {
            private: EscrowConfigPrivate,
            consensus: EscrowConfigConsensus {
                deposit_fee: Amount::ZERO,
            },
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<EscrowClientConfig> {
        let config = EscrowConfigConsensus::from_erased(config)?;
        Ok(EscrowClientConfig {
            deposit_fee: config.deposit_fee,
        })
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        _config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Escrow>> {
        BTreeMap::new()
    }
}

/// The escrow module
#[derive(Debug)]
pub struct Escrow {
    pub cfg: EscrowConfig,
}

/// Implementation of consensus for the server module
#[async_trait]
impl ServerModule for Escrow {
    /// Define the consensus types
    type Common = EscrowModuleTypes;
    type Init = EscrowInit;

    /// Propose pending oracle attestations accumulated in this guardian's DB
    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<EscrowConsensusItem> {
        dbtx.find_by_prefix(&AllPendingOracleAttestationsPrefix)
            .await
            .map(|(k, v)| EscrowConsensusItem::OracleAttestation {
                escrow_id: k.escrow_id,
                attestation: v,
            })
            .collect::<Vec<_>>()
            .await
    }

    /// Validate and store a confirmed oracle attestation from any peer
    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: EscrowConsensusItem,
        _peer_id: PeerId,
    ) -> anyhow::Result<()> {
        match consensus_item {
            EscrowConsensusItem::OracleAttestation { escrow_id, attestation } => {
                // Escrow must exist
                let Some(escrow_value) = dbtx
                    .get_value(&EscrowKey { escrow_id: escrow_id.clone() })
                    .await
                else {
                    bail!("Escrow not found: {escrow_id}");
                };

                // Validate the individual attestation
                oracle::verify_attestation(
                    &attestation,
                    &escrow_value.oracle_pubkeys,  // Vec<PublicKey> coerces to &[PublicKey]
                    &escrow_id,
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?;

                // Store (or overwrite) in pending attestation DB keyed by escrow + oracle pubkey
                let pending_key = PendingOracleAttestationKey {
                    escrow_id,
                    pubkey: attestation.pubkey,
                };
                dbtx.insert_entry(&pending_key, &attestation).await;
                Ok(())
            }
        }
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b EscrowInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, EscrowInputError> {
        match input {
            EscrowInput::ClamingWithoutDispute(escrow_input) => {
                let mut escrow_value = self
                    .get_escrow_value(dbtx, escrow_input.escrow_id.clone())
                    .await?;

                // check the signature of seller
                let secp = Secp256k1::new();
                let message = Message::from_digest_slice(&escrow_input.hashed_message).expect("32 bytes");
                let (xonly_pubkey, _parity) = escrow_value.seller_pubkey.x_only_public_key();

                if secp
                    .verify_schnorr(&escrow_input.signature, &message, &xonly_pubkey)
                    .is_err()
                {
                    return Err(EscrowInputError::InvalidSeller);
                }

                // the secret code when hashed should be the same as the one in the db
                if escrow_value.secret_code_hash != hash256(escrow_input.secret_code.clone()) {
                    return Err(EscrowInputError::InvalidSecretCode);
                }
                escrow_value.state = EscrowStates::ResolvedWithoutDispute;

                let escrow_key = EscrowKey {
                    escrow_id: escrow_input.escrow_id.clone(),
                };
                dbtx.insert_entry(&escrow_key, &escrow_value).await;

                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::new_bitcoin(escrow_input.amount),
                        fees: Amounts::ZERO,
                    },
                    pub_key: escrow_value.seller_pubkey,
                })
            }
            EscrowInput::Disputing(escrow_input) => {
                let mut escrow_value = self
                    .get_escrow_value(dbtx, escrow_input.escrow_id.clone())
                    .await?;

                // Determine who is disputing
                let disputer = if escrow_input.disputer == escrow_value.buyer_pubkey {
                    Disputer::Buyer
                } else if escrow_input.disputer == escrow_value.seller_pubkey {
                    Disputer::Seller
                } else {
                    return Err(EscrowInputError::UnauthorizedToDispute);
                };

                // check the signature of disputer
                let secp = Secp256k1::new();
                let message = Message::from_digest_slice(&escrow_input.hashed_message).expect("32 bytes");
                let xonly_pubkey = match disputer {
                    Disputer::Buyer => {
                        let (xonly, _parity) = escrow_value.buyer_pubkey.x_only_public_key();
                        xonly
                    }
                    Disputer::Seller => {
                        let (xonly, _parity) = escrow_value.seller_pubkey.x_only_public_key();
                        xonly
                    }
                };

                if secp
                    .verify_schnorr(&escrow_input.signature, &message, &xonly_pubkey)
                    .is_err()
                {
                    return Err(EscrowInputError::InvalidOracleSignature);
                }

                match escrow_value.state {
                    EscrowStates::Open => {
                        escrow_value.state = match disputer {
                            Disputer::Buyer => EscrowStates::DisputedByBuyer,
                            Disputer::Seller => EscrowStates::DisputedBySeller,
                        };
                    }
                    _ => return Err(EscrowInputError::InvalidStateForInitiatingDispute),
                }

                let escrow_key = EscrowKey {
                    escrow_id: escrow_input.escrow_id.clone(),
                };
                dbtx.insert_entry(&escrow_key, &escrow_value).await;

                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::ZERO,
                        fees: Amounts::ZERO,
                    },
                    pub_key: escrow_input.disputer,
                })
            }
            EscrowInput::OracleAttestation(escrow_input) => {
                let mut escrow_value = self
                    .get_escrow_value(dbtx, escrow_input.escrow_id.clone())
                    .await?;

                // Escrow must be in a disputed state for oracle resolution
                match escrow_value.state {
                    EscrowStates::DisputedByBuyer | EscrowStates::DisputedBySeller => {}
                    _ => return Err(EscrowInputError::InvalidStateForClaimingEscrow),
                }

                // Verify 2-of-3 oracle threshold
                let beneficiary = oracle::verify_threshold(
                    &escrow_input.attestations,
                    &escrow_value.oracle_pubkeys,  // Vec<PublicKey> coerces to &[PublicKey]
                    &escrow_input.escrow_id,
                )
                .map_err(|e| match e {
                    oracle::OracleVerifyError::InvalidSignature => {
                        EscrowInputError::InvalidOracleSignature
                    }
                    oracle::OracleVerifyError::UnknownOracle => EscrowInputError::UnknownOracle,
                    oracle::OracleVerifyError::EscrowIdMismatch => EscrowInputError::EscrowIdMismatch,
                    oracle::OracleVerifyError::ConflictingOutcomes => {
                        EscrowInputError::ConflictingOracleOutcomes
                    }
                    oracle::OracleVerifyError::ThresholdNotMet { .. } => {
                        EscrowInputError::OracleThresholdNotMet
                    }
                })?;

                escrow_value.state = EscrowStates::ResolvedByOracle;

                let escrow_key = EscrowKey {
                    escrow_id: escrow_input.escrow_id.clone(),
                };
                dbtx.insert_entry(&escrow_key, &escrow_value).await;

                // Winner gets the ecash
                let winner_pubkey = match beneficiary {
                    Beneficiary::Buyer => escrow_value.buyer_pubkey,
                    Beneficiary::Seller => escrow_value.seller_pubkey,
                };

                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::new_bitcoin(escrow_input.amount),
                        fees: Amounts::ZERO,
                    },
                    pub_key: winner_pubkey,
                })
            }
            EscrowInput::TimeoutClaim(escrow_input) => {
                let mut escrow_value = self
                    .get_escrow_value(dbtx, escrow_input.escrow_id.clone())
                    .await?;

                // Only open or disputed escrows can be claimed via timeout
                match escrow_value.state {
                    EscrowStates::Open
                    | EscrowStates::DisputedByBuyer
                    | EscrowStates::DisputedBySeller => {}
                    _ => return Err(EscrowInputError::InvalidStateForClaimingEscrow),
                }

                // Check that the timelock has expired
                let current_height = dbtx
                    .get_value(&BlockHeightKey)
                    .await
                    .ok_or(EscrowInputError::BlockHeightUnknown)?;
                if current_height < escrow_value.timeout_block as u64 {
                    return Err(EscrowInputError::TimelockNotExpired {
                        current: current_height,
                        required: escrow_value.timeout_block as u64,
                    });
                }

                // Determine who is authorized to claim based on timeout_action
                let (authorized_pubkey, auth_error) = match escrow_value.timeout_action {
                    TimeoutAction::Release => (escrow_value.seller_pubkey, EscrowInputError::InvalidSeller),
                    TimeoutAction::Refund => (escrow_value.buyer_pubkey, EscrowInputError::InvalidBuyer),
                };

                // Verify the claimant's signature
                let secp = Secp256k1::new();
                let message =
                    Message::from_digest_slice(&escrow_input.hashed_message).expect("32 bytes");
                let (xonly_pubkey, _parity) = authorized_pubkey.x_only_public_key();
                if secp
                    .verify_schnorr(&escrow_input.signature, &message, &xonly_pubkey)
                    .is_err()
                {
                    return Err(auth_error);
                }

                escrow_value.state = EscrowStates::TimedOut;

                let escrow_key = EscrowKey {
                    escrow_id: escrow_input.escrow_id.clone(),
                };
                dbtx.insert_entry(&escrow_key, &escrow_value).await;

                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::new_bitcoin(escrow_input.amount),
                        fees: Amounts::ZERO,
                    },
                    pub_key: authorized_pubkey,
                })
            }
        }
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a EscrowOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmounts, EscrowOutputError> {
        if self
            .get_escrow_value(dbtx, output.escrow_id.clone())
            .await
            .is_ok()
        {
            return Err(EscrowOutputError::EscrowAlreadyExists);
        }
        let escrow_key = EscrowKey {
            escrow_id: output.escrow_id.clone(),
        };
        // Validate exactly 3 oracle pubkeys
        if output.oracle_pubkeys.len() != 3 {
            return Err(EscrowOutputError::EscrowAlreadyExists); // reuse error for now
        }

        let escrow_value = EscrowValue {
            buyer_pubkey: output.buyer_pubkey,
            seller_pubkey: output.seller_pubkey,
            oracle_pubkeys: output.oracle_pubkeys.clone(),
            amount: output.amount,
            secret_code_hash: output.secret_code_hash.clone(),
            state: EscrowStates::Open,
            timeout_block: output.timeout_block,
            timeout_action: output.timeout_action.clone(),
        };

        dbtx.insert_new_entry(&escrow_key, &escrow_value).await;

        Ok(TransactionItemAmounts {
            amounts: Amounts::new_bitcoin(output.amount),
            fees: Amounts::new_bitcoin(self.cfg.consensus.deposit_fee),
        })
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<EscrowOutputOutcome> {
        Some(EscrowOutputOutcome {})
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        // Each locked escrow is a liability: the federation owes that ecash to the
        // winning party. We report negative amounts (liabilities).
        audit
            .add_items(dbtx, module_instance_id, &EscrowKeyPrefix, |_k, v| {
                // Only open/disputed escrows are still locked — resolved ones are gone
                match v.state {
                    EscrowStates::Open
                    | EscrowStates::DisputedByBuyer
                    | EscrowStates::DisputedBySeller => -(v.amount.msats as i64),
                    // Resolved/timed-out/oracle-resolved escrows have been paid out — no liability
                    EscrowStates::ResolvedWithoutDispute
                    | EscrowStates::ResolvedWithDispute
                    | EscrowStates::TimedOut
                    | EscrowStates::ResolvedByOracle => 0,
                }
            })
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![api_endpoint! {
            GET_MODULE_INFO,
            ApiVersion::new(0, 0),
            async |module: &Escrow, context, escrow_id: String| -> EscrowInfo {
                let db = context.db();
                let mut dbtx = db.begin_transaction_nc().await;
                module.handle_get_module_info(&mut dbtx, escrow_id).await
            }
        }]
    }
}

impl Escrow {
    /// Create new module instance
    pub fn new(cfg: EscrowConfig) -> Escrow {
        Escrow { cfg }
    }

    async fn handle_get_module_info(
        &self,
        dbtx: &mut DatabaseTransaction<'_, NonCommittable>,
        escrow_id: String,
    ) -> Result<EscrowInfo, ApiError> {
        let escrow_value: EscrowValue = dbtx
            .get_value(&EscrowKey { escrow_id })
            .await
            .ok_or_else(|| ApiError::not_found("Escrow not found".to_owned()))?;
        let escrow_info = EscrowInfo {
            buyer_pubkey: escrow_value.buyer_pubkey,
            seller_pubkey: escrow_value.seller_pubkey,
            oracle_pubkeys: escrow_value.oracle_pubkeys,
            amount: escrow_value.amount,
            secret_code_hash: escrow_value.secret_code_hash,
            state: escrow_value.state,
            timeout_block: escrow_value.timeout_block,
            timeout_action: escrow_value.timeout_action,
        };
        Ok(escrow_info)
    }

    async fn get_escrow_value<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        escrow_id: String,
    ) -> Result<EscrowValue, EscrowInputError> {
        let escrow_key = EscrowKey { escrow_id };
        dbtx.get_value(&escrow_key)
            .await
            .ok_or(EscrowInputError::EscrowNotFound)
    }
}
