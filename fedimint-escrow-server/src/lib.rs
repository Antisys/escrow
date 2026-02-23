mod db;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use anyhow::bail;
use async_trait::async_trait;
pub use db::EscrowValue;
use db::{BlockHeightKey, DbKeyPrefix, EscrowKey, EscrowKeyPrefix};
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
use fedimint_escrow_common::{
    hash256, ArbiterDecision, Disputer, EscrowCommonInit, EscrowConsensusItem, EscrowInput,
    EscrowInputError, EscrowModuleTypes, EscrowOutput, EscrowOutputError, EscrowOutputOutcome,
    EscrowStates, TimeoutAction, MODULE_CONSENSUS_VERSION,
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
                        max_arbiter_fee_bps: 1000, // 10% max arbiter fee
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
                max_arbiter_fee_bps: 1000,
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
            max_arbiter_fee_bps: config.max_arbiter_fee_bps,
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

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<EscrowConsensusItem> {
        Vec::new()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_item: EscrowConsensusItem,
        _peer_id: PeerId,
    ) -> anyhow::Result<()> {
        bail!("The escrow module does not use consensus items");
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

                // Update the escrow value in the database
                let escrow_key = EscrowKey {
                    escrow_id: escrow_input.escrow_id.clone(),
                };
                dbtx.insert_entry(&escrow_key, &escrow_value).await;

                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::new_bitcoin(escrow_input.amount),
                        fees: Amounts::ZERO,
                    },
                    pub_key: escrow_value.seller_pubkey, // seller gets the ecash
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
                    return Err(EscrowInputError::InvalidArbiter);
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

                // Update the escrow value in the database
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
            EscrowInput::ArbiterDecision(escrow_input) => {
                let mut escrow_value = self
                    .get_escrow_value(dbtx, escrow_input.escrow_id.clone())
                    .await?;

                // the escrow state should be disputed for the arbiter to take decision
                if escrow_value.state != EscrowStates::DisputedByBuyer
                    && escrow_value.state != EscrowStates::DisputedBySeller
                {
                    return Err(EscrowInputError::EscrowNotDisputed);
                }

                // check the signature of arbiter
                let secp = Secp256k1::new();
                let message = Message::from_digest_slice(&escrow_input.hashed_message).expect("32 bytes");
                let (xonly_pubkey, _parity) = escrow_value.arbiter_pubkey.x_only_public_key();

                if secp
                    .verify_schnorr(&escrow_input.signature, &message, &xonly_pubkey)
                    .is_err()
                {
                    return Err(EscrowInputError::InvalidArbiter);
                }

                // Validate arbiter's fee
                if escrow_input.amount > escrow_value.max_arbiter_fee {
                    return Err(EscrowInputError::ArbiterFeeExceedsMaximum);
                } else {
                    escrow_value.amount = escrow_value.amount
                        .checked_sub(escrow_input.amount)
                        .expect("arbiter fee already validated <= max_arbiter_fee");
                }

                // Update the escrow state based on the arbiter's decision
                match escrow_input.arbiter_decision {
                    ArbiterDecision::BuyerWins => {
                        escrow_value.state = EscrowStates::WaitingforBuyerToClaim;
                    }
                    ArbiterDecision::SellerWins => {
                        escrow_value.state = EscrowStates::WaitingforSellerToClaim;
                    }
                }

                // Update the escrow value in the database
                let escrow_key = EscrowKey {
                    escrow_id: escrow_input.escrow_id.clone(),
                };
                dbtx.insert_entry(&escrow_key, &escrow_value).await;

                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::new_bitcoin(escrow_input.amount),
                        fees: Amounts::ZERO,
                    },
                    pub_key: escrow_value.arbiter_pubkey, // arbiter gets their fee
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
            EscrowInput::ClaimingAfterDispute(escrow_input) => {
                let mut escrow_value = self
                    .get_escrow_value(dbtx, escrow_input.escrow_id.clone())
                    .await?;
                match escrow_value.state {
                    EscrowStates::WaitingforBuyerToClaim => {
                        // check the signature of buyer
                        let secp = Secp256k1::new();
                        let message =
                            Message::from_digest_slice(&escrow_input.hashed_message).expect("32 bytes");
                        let (xonly_pubkey, _parity) = escrow_value.buyer_pubkey.x_only_public_key();

                        if secp
                            .verify_schnorr(&escrow_input.signature, &message, &xonly_pubkey)
                            .is_err()
                        {
                            return Err(EscrowInputError::InvalidBuyer);
                        }
                        escrow_value.state = EscrowStates::ResolvedWithDispute;

                        // Update the escrow value in the database
                        let escrow_key = EscrowKey {
                            escrow_id: escrow_input.escrow_id.clone(),
                        };
                        dbtx.insert_entry(&escrow_key, &escrow_value).await;

                        Ok(InputMeta {
                            amount: TransactionItemAmounts {
                                amounts: Amounts::new_bitcoin(escrow_input.amount),
                                fees: Amounts::ZERO,
                            },
                            pub_key: escrow_value.buyer_pubkey, // FIX: buyer wins, buyer gets ecash
                        })
                    }
                    EscrowStates::WaitingforSellerToClaim => {
                        // check the signature of seller
                        let secp = Secp256k1::new();
                        let message =
                            Message::from_digest_slice(&escrow_input.hashed_message).expect("32 bytes");
                        let (xonly_pubkey, _parity) =
                            escrow_value.seller_pubkey.x_only_public_key();

                        if secp
                            .verify_schnorr(&escrow_input.signature, &message, &xonly_pubkey)
                            .is_err()
                        {
                            return Err(EscrowInputError::InvalidSeller);
                        }
                        escrow_value.state = EscrowStates::ResolvedWithDispute;

                        // Update the escrow value in the database
                        let escrow_key = EscrowKey {
                            escrow_id: escrow_input.escrow_id.clone(),
                        };
                        dbtx.insert_entry(&escrow_key, &escrow_value).await;

                        Ok(InputMeta {
                            amount: TransactionItemAmounts {
                                amounts: Amounts::new_bitcoin(escrow_input.amount),
                                fees: Amounts::ZERO,
                            },
                            pub_key: escrow_value.seller_pubkey, // seller wins, seller gets ecash
                        })
                    }
                    _ => Err(EscrowInputError::InvalidStateForClaimingEscrow),
                }
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
        let escrow_value = EscrowValue {
            buyer_pubkey: output.buyer_pubkey,
            seller_pubkey: output.seller_pubkey,
            arbiter_pubkey: output.arbiter_pubkey,
            amount: output.amount,
            secret_code_hash: output.secret_code_hash.clone(),
            max_arbiter_fee: output.max_arbiter_fee,
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
                    | EscrowStates::DisputedBySeller
                    | EscrowStates::WaitingforBuyerToClaim
                    | EscrowStates::WaitingforSellerToClaim => -(v.amount.msats as i64),
                    // Resolved/timed-out escrows have already been paid out — no liability
                    EscrowStates::ResolvedWithoutDispute
                    | EscrowStates::ResolvedWithDispute
                    | EscrowStates::TimedOut => 0,
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
            arbiter_pubkey: escrow_value.arbiter_pubkey,
            amount: escrow_value.amount,
            secret_code_hash: escrow_value.secret_code_hash,
            state: escrow_value.state,
            max_arbiter_fee: escrow_value.max_arbiter_fee,
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
