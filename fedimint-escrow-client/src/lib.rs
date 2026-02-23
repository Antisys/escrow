pub mod api;
pub mod cli;
pub mod states;

use std::sync::Arc;

use anyhow::Context as _;
use async_stream::stream;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule};
use fedimint_client_module::oplog::UpdateStreamOrOutcome;
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputBundle, ClientOutputSM,
    TransactionBuilder,
};
use fedimint_core::OutPointRange;
use fedimint_api_client::api::DynModuleApi;
use fedimint_core::core::OperationId;
use fedimint_core::db::{Database, DatabaseTransaction};
use fedimint_core::module::{
    ApiVersion, Amounts, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::secp256k1::{Keypair, Message, Secp256k1};
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint};
use fedimint_escrow_common::config::EscrowClientConfig;
use fedimint_escrow_common::endpoints::EscrowInfo;
use fedimint_escrow_common::{
    EscrowCommonInit, EscrowError, EscrowInput, EscrowInputClamingWithoutDispute,
    EscrowInputDisputing, EscrowModuleTypes, EscrowOutput, EscrowStates, KIND,
};
use futures::StreamExt;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api::EscrowFederationApi;
use crate::states::{EscrowClientContext, EscrowStateMachine};

/// The escrow client module
#[derive(Debug)]
pub struct EscrowClientModule {
    cfg: EscrowClientConfig,
    key: Keypair,
    client_ctx: ClientContext<Self>,
    pub module_api: DynModuleApi,
    db: Database,
}

/// The high level state for tracking operations of transactions
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum EscrowOperationState {
    /// The transaction is being processed by the federation
    Created,
    /// The transaction is accepted by the federation
    Accepted,
    /// The transaction is rejected by the federation
    Rejected,
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for EscrowClientModule {
    type Init = EscrowClientInit;
    type Common = EscrowModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = EscrowClientContext;
    type States = EscrowStateMachine;

    fn context(&self) -> Self::ModuleStateMachineContext {
        EscrowClientContext {
            escrow_decoder: EscrowModuleTypes::decoder(),
        }
    }

    /// Returns the fee the processing of this input requires (not the amount).
    fn input_fee(
        &self,
        _amount: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        Some(Amounts::ZERO)
    }

    /// Returns the fee the processing of this output requires.
    fn output_fee(
        &self,
        _amount: &Amounts,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(self.cfg.deposit_fee))
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }
}

impl EscrowClientModule {
    /// Creates an escrow — buyer locks ecash in the federation.
    /// oracle_pubkeys: the 3 Nostr oracle pubkeys; 2-of-3 needed for dispute resolution.
    pub async fn create_escrow(
        &self,
        amount: Amount,
        seller_pubkey: fedimint_core::secp256k1::PublicKey,
        oracle_pubkeys: Vec<fedimint_core::secp256k1::PublicKey>,
        escrow_id: String,
        secret_code_hash: String,
        timeout_block: u32,
        timeout_action: fedimint_escrow_common::TimeoutAction,
    ) -> anyhow::Result<()> {
        if oracle_pubkeys.len() != 3 {
            return Err(anyhow::anyhow!("oracle_pubkeys must contain exactly 3 public keys"));
        }
        let operation_id = OperationId(thread_rng().gen());

        let output = EscrowOutput {
            amount,
            buyer_pubkey: self.key.public_key(),
            seller_pubkey,
            oracle_pubkeys,
            escrow_id,
            secret_code_hash,
            timeout_block,
            timeout_action,
        };

        let operation_id_clone = operation_id;
        let client_output = ClientOutput {
            output,
            amounts: Amounts::new_bitcoin(amount),
        };
        let output_sm = ClientOutputSM {
            state_machines: Arc::new(move |_: OutPointRange| {
                vec![EscrowStateMachine {
                    operation_id: operation_id_clone,
                }]
            }),
        };

        let tx = TransactionBuilder::new().with_outputs(
            self.client_ctx
                .make_client_outputs(ClientOutputBundle::new(vec![client_output], vec![output_sm])),
        );
        let out_point_range = self
            .client_ctx
            .finalize_and_submit_transaction(operation_id, KIND.as_str(), |_| (), tx)
            .await?;

        let mut updates = self
            .subscribe_transactions_input(operation_id, out_point_range)
            .await
            .unwrap()
            .into_stream();

        while let Some(update) = updates.next().await {
            match update {
                EscrowOperationState::Created | EscrowOperationState::Accepted => {}
                EscrowOperationState::Rejected => {
                    return Err(anyhow::anyhow!(EscrowError::TransactionRejected));
                }
            }
        }

        Ok(())
    }

    /// Seller claims the escrow by providing the secret code (cooperative, no dispute).
    pub async fn claim_escrow(
        &self,
        escrow_id: String,
        amount: Amount,
        secret_code: String,
    ) -> anyhow::Result<()> {
        let escrow_value: EscrowInfo = self.module_api.get_escrow_info(escrow_id.clone()).await?;

        // Only Open escrows can be claimed cooperatively
        if escrow_value.state == EscrowStates::DisputedByBuyer
            || escrow_value.state == EscrowStates::DisputedBySeller
        {
            return Err(anyhow::anyhow!(EscrowError::EscrowDisputed));
        }
        if escrow_value.state != EscrowStates::Open {
            return Err(anyhow::anyhow!(EscrowError::EscrowNotFound));
        }

        let secp = Secp256k1::new();
        let mut hasher = Sha256::new();
        hasher.update(secret_code.as_bytes());
        let hashed_message: [u8; 32] = hasher.finalize().into();
        let message = Message::from_digest_slice(&hashed_message).expect("32 bytes");
        let signature = secp.sign_schnorr(&message, &self.key);

        let operation_id = OperationId(thread_rng().gen());
        let input = EscrowInput::ClamingWithoutDispute(EscrowInputClamingWithoutDispute {
            amount,
            escrow_id,
            secret_code,
            hashed_message,
            signature,
        });

        let operation_id_clone = operation_id;
        let client_input = ClientInput {
            input,
            keys: vec![self.key],
            amounts: Amounts::new_bitcoin(amount),
        };
        let input_sm = ClientInputSM {
            state_machines: Arc::new(move |_: OutPointRange| {
                vec![EscrowStateMachine {
                    operation_id: operation_id_clone,
                }]
            }),
        };

        let tx = TransactionBuilder::new().with_inputs(
            self.client_ctx
                .make_client_inputs(ClientInputBundle::new(vec![client_input], vec![input_sm])),
        );
        let out_point_range = self
            .client_ctx
            .finalize_and_submit_transaction(operation_id, KIND.as_str(), |_| (), tx)
            .await?;

        let mut updates = self
            .subscribe_transactions_output(operation_id, out_point_range)
            .await
            .unwrap()
            .into_stream();

        while let Some(update) = updates.next().await {
            match update {
                EscrowOperationState::Created | EscrowOperationState::Accepted => {}
                EscrowOperationState::Rejected => {
                    return Err(anyhow::anyhow!(EscrowError::TransactionRejected));
                }
            }
        }

        Ok(())
    }

    /// Initiates a dispute (buyer or seller can call this).
    pub async fn initiate_dispute(&self, escrow_id: String) -> anyhow::Result<()> {
        let operation_id = OperationId(thread_rng().gen());

        let secp = Secp256k1::new();
        let mut hasher = Sha256::new();
        hasher.update("dispute".as_bytes());
        let hashed_message: [u8; 32] = hasher.finalize().into();
        let message = Message::from_digest_slice(&hashed_message).expect("32 bytes");
        let signature = secp.sign_schnorr(&message, &self.key);

        let input = EscrowInput::Disputing(EscrowInputDisputing {
            escrow_id,
            disputer: self.key.public_key(),
            hashed_message,
            signature,
        });

        let operation_id_clone = operation_id;
        let client_input = ClientInput {
            input,
            keys: vec![self.key],
            amounts: Amounts::ZERO,
        };
        let input_sm = ClientInputSM {
            state_machines: Arc::new(move |_: OutPointRange| {
                vec![EscrowStateMachine {
                    operation_id: operation_id_clone,
                }]
            }),
        };

        let tx = TransactionBuilder::new().with_inputs(
            self.client_ctx
                .make_client_inputs(ClientInputBundle::new(vec![client_input], vec![input_sm])),
        );
        let out_point_range = self
            .client_ctx
            .finalize_and_submit_transaction(operation_id, KIND.as_str(), |_| (), tx)
            .await?;

        let mut updates = self
            .subscribe_transactions_output(operation_id, out_point_range)
            .await
            .unwrap()
            .into_stream();

        while let Some(update) = updates.next().await {
            match update {
                EscrowOperationState::Created | EscrowOperationState::Accepted => {}
                EscrowOperationState::Rejected => {
                    return Err(anyhow::anyhow!(EscrowError::TransactionRejected));
                }
            }
        }

        Ok(())
    }

    /// Subscribes to transaction updates for operations with no ecash output (e.g. dispute).
    pub async fn subscribe_transactions_input(
        &self,
        operation_id: OperationId,
        out_point_range: OutPointRange,
    ) -> anyhow::Result<UpdateStreamOrOutcome<EscrowOperationState>> {
        let tx_subscription = self.client_ctx.transaction_updates(operation_id).await;
        let txid = out_point_range.txid();

        Ok(UpdateStreamOrOutcome::UpdateStream(Box::pin(stream! {
            yield EscrowOperationState::Created;

            match tx_subscription.await_tx_accepted(txid).await {
                Ok(()) => {
                    yield EscrowOperationState::Accepted;
                },
                Err(e) => {
                    tracing::info!("Transaction rejected: {:?}", e);
                    yield EscrowOperationState::Rejected;
                }
            }
        })))
    }

    /// Subscribes to transaction updates for operations that generate ecash change outputs.
    pub async fn subscribe_transactions_output(
        &self,
        operation_id: OperationId,
        out_point_range: OutPointRange,
    ) -> anyhow::Result<UpdateStreamOrOutcome<EscrowOperationState>> {
        let tx_subscription = self.client_ctx.transaction_updates(operation_id).await;
        let client_ctx = self.client_ctx.clone();
        let txid = out_point_range.txid();
        let change: Vec<OutPoint> = out_point_range.into_iter().collect();

        Ok(UpdateStreamOrOutcome::UpdateStream(Box::pin(stream! {
            yield EscrowOperationState::Created;

            match tx_subscription.await_tx_accepted(txid).await {
                Ok(()) => {
                    match client_ctx
                        .await_primary_module_outputs(operation_id, change)
                        .await
                        .context("Ensuring that the transaction is successful!") {
                        Ok(_) => yield EscrowOperationState::Accepted,
                        Err(_) => yield EscrowOperationState::Rejected,
                    }
                },
                Err(e) => {
                    tracing::info!("Transaction rejected: {:?}", e);
                    yield EscrowOperationState::Rejected;
                }
            }
        })))
    }
}

/// The escrow client module initializer
#[derive(Debug, Clone)]
pub struct EscrowClientInit;

impl ModuleInit for EscrowClientInit {
    type Common = EscrowCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(std::iter::empty())
    }
}

/// Generates the client module
#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for EscrowClientInit {
    type Module = EscrowClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        let cfg = args.cfg().clone();
        Ok(EscrowClientModule {
            cfg: cfg.clone(),
            module_api: args.module_api().clone(),
            key: args
                .module_root_secret()
                .clone()
                .to_secp_key(&Secp256k1::new()),
            client_ctx: args.context(),
            db: args.db().clone(),
        })
    }
}
