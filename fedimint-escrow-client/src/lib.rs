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
use fedimint_ln_client::LightningClientModule;
use fedimint_escrow_common::config::EscrowClientConfig;
use fedimint_escrow_common::endpoints::EscrowInfo;
use fedimint_escrow_common::oracle::SignedAttestation;
use fedimint_escrow_common::{
    EscrowCommonInit, EscrowError, EscrowInput, EscrowInputClaimDelegated,
    EscrowInputClaimWithoutDispute, EscrowInputDisputeDelegated, EscrowInputDisputing,
    EscrowInputOracleAttestation, EscrowInputTimeoutClaim, EscrowInputTimeoutClaimDelegated,
    EscrowModuleTypes, EscrowOutput, EscrowStates, KIND,
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
    pub key: Keypair,
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
        buyer_pubkey: Option<fedimint_core::secp256k1::PublicKey>,
    ) -> anyhow::Result<()> {
        if oracle_pubkeys.len() != 3 {
            return Err(anyhow::anyhow!("oracle_pubkeys must contain exactly 3 public keys"));
        }
        let operation_id = OperationId(thread_rng().gen());

        let output = EscrowOutput {
            amount,
            buyer_pubkey: buyer_pubkey.unwrap_or_else(|| self.key.public_key()),
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

        let amount = escrow_value.amount;
        let secp = Secp256k1::new();
        let mut hasher = Sha256::new();
        hasher.update(secret_code.as_bytes());
        let hashed_message: [u8; 32] = hasher.finalize().into();
        let message = Message::from_digest_slice(&hashed_message).expect("32 bytes");
        let signature = secp.sign_schnorr(&message, &self.key);

        let operation_id = OperationId(thread_rng().gen());
        let input = EscrowInput::ClaimWithoutDispute(EscrowInputClaimWithoutDispute {
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

    /// Resolves a disputed escrow via 2-of-3 oracle attestations.
    /// The winning party (buyer or seller) receives the escrow amount as ecash.
    /// Attestations must include at least 2 agreeing signatures from the registered oracle set.
    pub async fn resolve_via_oracle(
        &self,
        escrow_id: String,
        attestations: Vec<SignedAttestation>,
    ) -> anyhow::Result<()> {
        let escrow_value: EscrowInfo = self.module_api.get_escrow_info(escrow_id.clone()).await?;

        // Only disputed escrows can be resolved via oracle
        if escrow_value.state != EscrowStates::DisputedByBuyer
            && escrow_value.state != EscrowStates::DisputedBySeller
        {
            return Err(anyhow::anyhow!(EscrowError::EscrowNotFound));
        }

        let operation_id = OperationId(thread_rng().gen());
        let input = EscrowInput::OracleAttestation(EscrowInputOracleAttestation {
            amount: escrow_value.amount,
            escrow_id,
            attestations,
            submitter_pubkey: self.key.public_key(),
        });

        let operation_id_clone = operation_id;
        let client_input = ClientInput {
            input,
            keys: vec![self.key],
            amounts: Amounts::new_bitcoin(escrow_value.amount),
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

    /// Claims an escrow after the timelock has expired.
    /// The caller must be the party authorized by `timeout_action`:
    /// - `TimeoutAction::Refund` → buyer reclaims
    /// - `TimeoutAction::Release` → seller claims
    pub async fn claim_timeout(&self, escrow_id: String) -> anyhow::Result<()> {
        let escrow_value: EscrowInfo = self.module_api.get_escrow_info(escrow_id.clone()).await?;

        // Only Open escrows can be claimed via timeout (disputed escrows use oracle path)
        if escrow_value.state != EscrowStates::Open {
            return Err(anyhow::anyhow!(EscrowError::EscrowNotFound));
        }

        let secp = Secp256k1::new();
        let mut hasher = Sha256::new();
        hasher.update("timeout".as_bytes());
        let hashed_message: [u8; 32] = hasher.finalize().into();
        let message = Message::from_digest_slice(&hashed_message).expect("32 bytes");
        let signature = secp.sign_schnorr(&message, &self.key);

        let operation_id = OperationId(thread_rng().gen());
        let input = EscrowInput::TimeoutClaim(EscrowInputTimeoutClaim {
            amount: escrow_value.amount,
            escrow_id,
            hashed_message,
            signature,
        });

        let operation_id_clone = operation_id;
        let client_input = ClientInput {
            input,
            keys: vec![self.key],
            amounts: Amounts::new_bitcoin(escrow_value.amount),
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

    // --- Delegated variants: user signs externally, service submits ---
    // E-cash goes to service (self.key) for LN payout. User's external signature proves consent.

    /// Delegated claim: buyer signed externally, service submits and receives e-cash for LN payout.
    pub async fn claim_escrow_delegated(
        &self,
        escrow_id: String,
        secret_code: String,
        external_signature: secp256k1::schnorr::Signature,
    ) -> anyhow::Result<()> {
        let escrow_value: EscrowInfo = self.module_api.get_escrow_info(escrow_id.clone()).await?;

        if escrow_value.state != EscrowStates::Open {
            return Err(anyhow::anyhow!(EscrowError::EscrowNotFound));
        }

        let amount = escrow_value.amount;
        let mut hasher = Sha256::new();
        hasher.update(secret_code.as_bytes());
        let hashed_message: [u8; 32] = hasher.finalize().into();

        let operation_id = OperationId(thread_rng().gen());
        let input = EscrowInput::ClaimDelegated(EscrowInputClaimDelegated {
            amount,
            escrow_id,
            secret_code,
            hashed_message,
            external_signature,
            submitter_pubkey: self.key.public_key(),
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

    /// Delegated timeout claim: authorized party signed externally, service submits.
    pub async fn claim_timeout_delegated(
        &self,
        escrow_id: String,
        external_signature: secp256k1::schnorr::Signature,
    ) -> anyhow::Result<()> {
        let escrow_value: EscrowInfo = self.module_api.get_escrow_info(escrow_id.clone()).await?;

        let mut hasher = Sha256::new();
        hasher.update("timeout".as_bytes());
        let hashed_message: [u8; 32] = hasher.finalize().into();

        let operation_id = OperationId(thread_rng().gen());
        let input = EscrowInput::TimeoutClaimDelegated(EscrowInputTimeoutClaimDelegated {
            amount: escrow_value.amount,
            escrow_id,
            hashed_message,
            external_signature,
            submitter_pubkey: self.key.public_key(),
        });

        let operation_id_clone = operation_id;
        let client_input = ClientInput {
            input,
            keys: vec![self.key],
            amounts: Amounts::new_bitcoin(escrow_value.amount),
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

    /// Delegated dispute: user signed externally, service submits.
    pub async fn initiate_dispute_delegated(
        &self,
        escrow_id: String,
        disputer_pubkey: fedimint_core::secp256k1::PublicKey,
        external_signature: secp256k1::schnorr::Signature,
    ) -> anyhow::Result<()> {
        let mut hasher = Sha256::new();
        hasher.update("dispute".as_bytes());
        let hashed_message: [u8; 32] = hasher.finalize().into();

        let operation_id = OperationId(thread_rng().gen());
        let input = EscrowInput::DisputeDelegated(EscrowInputDisputeDelegated {
            escrow_id,
            disputer: disputer_pubkey,
            hashed_message,
            external_signature,
            submitter_pubkey: self.key.public_key(),
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

    /// Delegated claim + LN pay: buyer signed externally, service claims and pays via LN.
    pub async fn claim_delegated_and_pay(
        &self,
        escrow_id: String,
        secret_code: String,
        external_signature: secp256k1::schnorr::Signature,
        bolt11_str: String,
    ) -> anyhow::Result<serde_json::Value> {
        self.claim_escrow_delegated(escrow_id.clone(), secret_code, external_signature).await?;
        let result = self.pay_via_ln_module(bolt11_str).await?;
        Ok(serde_json::json!({
            "escrow_id": escrow_id,
            "payment": result,
        }))
    }

    /// Delegated timeout claim + LN pay: authorized party signed externally, service claims and pays via LN.
    pub async fn claim_timeout_delegated_and_pay(
        &self,
        escrow_id: String,
        external_signature: secp256k1::schnorr::Signature,
        bolt11_str: String,
    ) -> anyhow::Result<serde_json::Value> {
        self.claim_timeout_delegated(escrow_id.clone(), external_signature).await?;
        let result = self.pay_via_ln_module(bolt11_str).await?;
        Ok(serde_json::json!({
            "escrow_id": escrow_id,
            "payment": result,
        }))
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

    /// Claims an escrow cooperatively (secret_code) and immediately pays via Lightning.
    ///
    /// This is a single CLI-level operation: claim → brief e-cash in wallet → LN pay.
    /// The Python service never sees the intermediate e-cash state.
    pub async fn claim_and_pay(
        &self,
        escrow_id: String,
        secret_code: String,
        bolt11_str: String,
    ) -> anyhow::Result<serde_json::Value> {
        // Step 1: claim the escrow cooperatively
        self.claim_escrow(escrow_id.clone(), secret_code).await?;

        // Step 2: parse invoice and pay via LN module
        let result = self.pay_via_ln_module(bolt11_str).await?;

        Ok(serde_json::json!({
            "escrow_id": escrow_id,
            "payment": result,
        }))
    }

    /// Claims an escrow after timeout and immediately pays via Lightning.
    ///
    /// This is a single CLI-level operation: claim-timeout → brief e-cash → LN pay.
    pub async fn claim_timeout_and_pay(
        &self,
        escrow_id: String,
        bolt11_str: String,
    ) -> anyhow::Result<serde_json::Value> {
        // Step 1: claim via timeout
        self.claim_timeout(escrow_id.clone()).await?;

        // Step 2: pay via LN module
        let result = self.pay_via_ln_module(bolt11_str).await?;

        Ok(serde_json::json!({
            "escrow_id": escrow_id,
            "payment": result,
        }))
    }

    /// Internal helper: find LN module instance, select gateway, and pay invoice.
    pub async fn pay_via_ln_module(&self, bolt11_str: String) -> anyhow::Result<serde_json::Value> {
        use lightning_invoice::Bolt11Invoice;

        // Find LN module instance ID from config
        let config = self.client_ctx.get_config().await;
        let ln_kind = LightningClientModule::kind();
        let ln_instance_id = config
            .modules
            .iter()
            .find(|(_, cfg)| cfg.kind == ln_kind)
            .map(|(id, _)| *id)
            .ok_or_else(|| anyhow::anyhow!("No Lightning module found in federation config"))?;

        // Downcast to typed LightningClientModule
        let iface = self.client_ctx.iface();
        let dyn_module = iface.get_module(ln_instance_id);
        let ln: &LightningClientModule = dyn_module
            .as_any()
            .downcast_ref::<LightningClientModule>()
            .ok_or_else(|| anyhow::anyhow!("Failed to access Lightning module"))?;

        // Parse invoice
        let invoice: Bolt11Invoice = bolt11_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid BOLT11 invoice: {e}"))?;

        // Network check removed: GlobalClientConfig no longer has `network` field in upstream.

        // Select best available gateway
        let gateway = ln.select_available_gateway(None, Some(invoice.clone())).await?;

        // Pay the invoice
        let payment = ln.pay_bolt11_invoice(Some(gateway), invoice, ()).await?;
        let operation_id = payment.payment_type.operation_id();

        // Await completion
        let outcome = ln.await_outgoing_payment(operation_id).await?;

        match outcome {
            fedimint_ln_client::LightningPaymentOutcome::Success { preimage } => {
                Ok(serde_json::json!({
                    "status": "success",
                    "preimage": preimage,
                    "operation_id": operation_id.fmt_full().to_string(),
                }))
            }
            fedimint_ln_client::LightningPaymentOutcome::Failure { error_message } => {
                Err(anyhow::anyhow!("LN payment failed: {error_message}"))
            }
        }
    }

    /// Create a LN receive invoice. When the buyer pays it, call `await_receive_into_escrow()`
    /// to atomically lock funds into a Fedimint escrow.
    ///
    /// Returns `{bolt11, escrow_id, operation_id}`.
    /// Window ①: buyer pays bolt11 → service wallet briefly holds e-cash → escrow locked.
    /// `await_receive_into_escrow()` collapses this into a single atomic CLI call.
    pub async fn receive_into_escrow(
        &self,
        amount: Amount,
        seller_pubkey: fedimint_core::secp256k1::PublicKey,
        oracle_pubkeys: Vec<fedimint_core::secp256k1::PublicKey>,
        secret_code_hash: String,
        timeout_block: u32,
        timeout_action: fedimint_escrow_common::TimeoutAction,
        gateway_id: Option<fedimint_core::secp256k1::PublicKey>,
        buyer_pubkey: Option<fedimint_core::secp256k1::PublicKey>,
        invoice_description: Option<String>,
    ) -> anyhow::Result<serde_json::Value> {
        use random_string::generate;

        if oracle_pubkeys.len() != 3 {
            return Err(anyhow::anyhow!("oracle_pubkeys must contain exactly 3 public keys"));
        }

        // Generate escrow ID — same mechanism as `create_escrow`
        let escrow_id = generate(
            32,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        );

        // Access LN module
        let config = self.client_ctx.get_config().await;
        let ln_kind = LightningClientModule::kind();
        let ln_instance_id = config
            .modules
            .iter()
            .find(|(_, cfg)| cfg.kind == ln_kind)
            .map(|(id, _)| *id)
            .ok_or_else(|| anyhow::anyhow!("No Lightning module found in federation config"))?;
        let iface = self.client_ctx.iface();
        let dyn_module = iface.get_module(ln_instance_id);
        let ln = dyn_module
            .as_any()
            .downcast_ref::<LightningClientModule>()
            .ok_or_else(|| anyhow::anyhow!("Failed to access Lightning module"))?;

        // Select a gateway so the invoice includes real LN route hints.
        // Uses get_gateway() which checks cache first, then refreshes if not found.
        // When gateway_id is Some, selects that specific gateway.
        // When None, picks a random available gateway (not internal).
        let gateway = ln.get_gateway(gateway_id, false).await?;

        // Create LN receive invoice
        let description_str = invoice_description.unwrap_or_else(|| format!("Escrow: {}", escrow_id));
        let description = lightning_invoice::Description::new(description_str)
            .map_err(|e| anyhow::anyhow!("Invalid invoice description: {:?}", e))?;
        let desc = lightning_invoice::Bolt11InvoiceDescription::Direct(description);

        let (ln_op_id, bolt11, _preimage) = ln
            .create_bolt11_invoice(amount, desc, Some(3600), (), gateway)
            .await?;

        let mut result = serde_json::json!({
            "bolt11": bolt11.to_string(),
            "escrow_id": escrow_id,
            "operation_id": ln_op_id.fmt_full().to_string(),
        });
        if let Some(bp) = buyer_pubkey {
            result["buyer_pubkey"] = serde_json::Value::String(bp.to_string());
        }
        Ok(result)
    }

    /// Poll the LN receive operation. When the buyer's payment is confirmed (`Claimed`),
    /// atomically create the Fedimint escrow — Window ① is eliminated at the Rust level.
    ///
    /// Idempotent: if the escrow already exists, returns `{status: "funded"}` immediately.
    /// Returns `{status: "awaiting"|"funded"|"failed", escrow_id, reason?}`.
    pub async fn await_receive_into_escrow(
        &self,
        ln_op_id_str: String,
        escrow_id: String,
        amount: Amount,
        seller_pubkey: fedimint_core::secp256k1::PublicKey,
        oracle_pubkeys: Vec<fedimint_core::secp256k1::PublicKey>,
        secret_code_hash: String,
        timeout_block: u32,
        timeout_action: fedimint_escrow_common::TimeoutAction,
        timeout_secs: u64,
        buyer_pubkey: Option<fedimint_core::secp256k1::PublicKey>,
    ) -> anyhow::Result<serde_json::Value> {
        // Idempotency: if escrow already created, return immediately
        if self.module_api.get_escrow_info(escrow_id.clone()).await.is_ok() {
            return Ok(serde_json::json!({
                "status": "funded",
                "escrow_id": escrow_id,
            }));
        }

        // Parse LN operation ID from hex string
        let ln_op_id: OperationId = ln_op_id_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid operation_id: {e}"))?;

        // Access LN module
        let config = self.client_ctx.get_config().await;
        let ln_kind = LightningClientModule::kind();
        let ln_instance_id = config
            .modules
            .iter()
            .find(|(_, cfg)| cfg.kind == ln_kind)
            .map(|(id, _)| *id)
            .ok_or_else(|| anyhow::anyhow!("No Lightning module found in federation config"))?;
        let iface = self.client_ctx.iface();
        let dyn_module = iface.get_module(ln_instance_id);
        let ln = dyn_module
            .as_any()
            .downcast_ref::<LightningClientModule>()
            .ok_or_else(|| anyhow::anyhow!("Failed to access Lightning module"))?;

        // Subscribe to LN receive state updates (replays all historical states)
        let mut updates = ln.subscribe_ln_receive(ln_op_id).await?.into_stream();

        let deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);
        let mut status = "awaiting";
        let mut cancel_reason: Option<String> = None;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, updates.next()).await {
                Ok(Some(state)) => match state {
                    fedimint_ln_client::LnReceiveState::Claimed => {
                        status = "funded";
                        break;
                    }
                    fedimint_ln_client::LnReceiveState::Canceled { reason } => {
                        status = "failed";
                        cancel_reason = Some(format!("{:?}", reason));
                        break;
                    }
                    _ => {
                        // WaitingForPayment, Funded, AwaitingFunds — keep polling
                    }
                },
                Ok(None) => break,      // stream ended
                Err(_timeout) => break, // poll timeout reached
            }
        }

        // If LN payment confirmed, create the escrow NOW
        // The e-cash is briefly in the wallet during create_escrow() — this is the
        // minimized Window ①: milliseconds inside one CLI call, invisible to Python.
        if status == "funded" {
            self.create_escrow(
                amount,
                seller_pubkey,
                oracle_pubkeys,
                escrow_id.clone(),
                secret_code_hash,
                timeout_block,
                timeout_action,
                buyer_pubkey,
            )
            .await?;
        }

        let mut result = serde_json::json!({
            "status": status,
            "escrow_id": escrow_id,
        });
        if let Some(reason) = cancel_reason {
            result["reason"] = serde_json::Value::String(reason);
        }
        Ok(result)
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
