//! escrow-httpd: persistent HTTP daemon for the Fedimint escrow module.
//!
//! Keeps a fedimint Client alive and exposes REST endpoints, eliminating
//! the ~13s cold-start overhead of spawning fedimint-cli per request.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use clap::Parser;
use fedimint_bip39::{Bip39RootSecretStrategy, Mnemonic};
use fedimint_client::{Client, ClientHandleArc, RootSecret};
use fedimint_client::secret::RootSecretStrategy;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::Amount;
use fedimint_core::secp256k1::PublicKey;
use fedimint_escrow_client::EscrowClientInit;
use fedimint_escrow_client::EscrowClientModule;
use fedimint_escrow_client::api::EscrowFederationApi;
use fedimint_escrow_common::TimeoutAction;
use fedimint_escrow_common::oracle::SignedAttestation;
use fedimint_ln_client::{LightningClientInit, LightningClientModule, LnReceiveState};
use fedimint_logging::TracingSetup;
use fedimint_mint_client::MintClientInit;
use fedimint_wallet_client::WalletClientInit;
use futures::StreamExt;
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Debug, Parser)]
#[command(name = "escrow-httpd", about = "Persistent HTTP daemon for Fedimint escrow")]
struct CliOpts {
    /// Path to the fedimint client data directory (with client.db)
    #[clap(long, env = "FM_DATA_DIR")]
    data_dir: PathBuf,

    /// Address to bind the HTTP server
    #[clap(long, default_value = "127.0.0.1:5400", env = "ESCROW_HTTPD_BIND")]
    bind: SocketAddr,
}

#[derive(Clone)]
struct AppState {
    client: ClientHandleArc,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;
    let opts = CliOpts::parse();

    info!("Opening database at {:?}", opts.data_dir);
    let db_path = opts.data_dir.join("client.db");
    let db: fedimint_core::db::Database = fedimint_rocksdb::RocksDb::build(db_path)
        .open()
        .await?
        .into();

    // Load mnemonic from existing client database
    let entropy = Client::load_decodable_client_secret::<Vec<u8>>(&db).await?;
    let mnemonic = Mnemonic::from_entropy(&entropy)?;

    // Build client with all required modules
    let connectors = ConnectorRegistry::build_from_client_defaults()
        .bind()
        .await?;

    let mut builder = Client::builder().await?;
    builder.with_module(EscrowClientInit);
    builder.with_module(LightningClientInit::default());
    builder.with_module(MintClientInit);
    builder.with_module(WalletClientInit::default());

    let client = builder
        .open(
            connectors,
            db,
            RootSecret::StandardDoubleDerive(
                Bip39RootSecretStrategy::<12>::to_root_secret(&mnemonic),
            ),
        )
        .await
        .map(Arc::new)?;

    // Verify escrow module is accessible
    let escrow_inst = client.get_first_module::<EscrowClientModule>()?;
    let pubkey = escrow_inst.module.key.public_key();
    info!("Escrow module loaded, service pubkey: {pubkey}");
    drop(escrow_inst);

    let state = AppState { client };

    let app = axum::Router::new()
        // Read-only queries
        .route("/info", get(handle_info))
        .route("/escrow/public-key", get(handle_public_key))
        .route("/escrow/{id}/info", get(handle_escrow_info))
        .route("/block-height", get(handle_block_height))
        // Escrow operations
        .route("/escrow/receive-into-escrow", post(handle_receive_into_escrow))
        .route("/escrow/await-receive", post(handle_await_receive))
        .route("/escrow/claim-delegated-and-pay", post(handle_claim_delegated_and_pay))
        .route("/escrow/claim-timeout-delegated-and-pay", post(handle_claim_timeout_delegated_and_pay))
        .route("/escrow/dispute-delegated", post(handle_dispute_delegated))
        .route("/escrow/resolve-oracle", post(handle_resolve_oracle))
        .route("/escrow/resolve-oracle-and-pay", post(handle_resolve_oracle_and_pay))
        .route("/escrow/claim-and-pay", post(handle_claim_and_pay))
        .route("/escrow/claim-timeout-and-pay", post(handle_claim_timeout_and_pay))
        .route("/escrow/await-invoice", post(handle_await_invoice))
        .with_state(state);

    info!("escrow-httpd listening on {}", opts.bind);
    let listener = TcpListener::bind(&opts.bind).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────

fn parse_pubkey(hex: &str) -> Result<PublicKey, ApiError> {
    hex.parse::<PublicKey>()
        .map_err(|e| ApiError(anyhow::anyhow!("Invalid public key '{hex}': {e}")))
}

fn parse_signature(hex: &str) -> Result<secp256k1::schnorr::Signature, ApiError> {
    let bytes = hex::decode(hex)
        .map_err(|e| ApiError(anyhow::anyhow!("Invalid signature hex: {e}")))?;
    secp256k1::schnorr::Signature::from_slice(&bytes)
        .map_err(|e| ApiError(anyhow::anyhow!("Invalid Schnorr signature: {e}")))
}

fn parse_timeout_action(s: &str) -> Result<TimeoutAction, ApiError> {
    match s {
        "release" => Ok(TimeoutAction::Release),
        "refund" => Ok(TimeoutAction::Refund),
        other => Err(ApiError(anyhow::anyhow!("Invalid timeout_action: '{other}' (must be 'release' or 'refund')"))),
    }
}

// ── GET /info ──────────────────────────────────────────────────────────

async fn handle_info(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let balance = state.client.get_balance_for_btc().await?;
    Ok(Json(json!({
        "total_amount_msat": balance.msats,
    })))
}

// ── GET /escrow/public-key ─────────────────────────────────────────────

async fn handle_public_key(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let escrow = state.client.get_first_module::<EscrowClientModule>()?;
    let pubkey = escrow.module.key.public_key();
    Ok(Json(json!({
        "public_key": pubkey.to_string(),
    })))
}

// ── GET /escrow/{id}/info ──────────────────────────────────────────────

async fn handle_escrow_info(
    State(state): State<AppState>,
    Path(escrow_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let escrow = state.client.get_first_module::<EscrowClientModule>()?;
    let info = escrow.module.module_api.get_escrow_info(escrow_id).await?;
    Ok(Json(serde_json::to_value(info)?))
}

// ── GET /block-height ──────────────────────────────────────────────────

async fn handle_block_height(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    use fedimint_wallet_client::WalletClientModule;
    use fedimint_wallet_client::api::WalletFederationApi;
    let wallet = state.client.get_first_module::<WalletClientModule>()?;
    let count = wallet.api.fetch_consensus_block_count().await?;
    Ok(Json(json!(count)))
}

// ── POST /escrow/receive-into-escrow ───────────────────────────────────

#[derive(Deserialize)]
struct ReceiveIntoEscrowReq {
    seller_pubkey: String,
    oracle_pubkeys: Vec<String>,
    amount_msats: u64,
    timeout_block: u32,
    timeout_action: String,
    secret_code_hash: String,
    gateway_id: Option<String>,
    buyer_pubkey: Option<String>,
    description: Option<String>,
}

async fn handle_receive_into_escrow(
    State(state): State<AppState>,
    Json(req): Json<ReceiveIntoEscrowReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let seller_pk = parse_pubkey(&req.seller_pubkey)?;
    let oracle_pks: Vec<PublicKey> = req.oracle_pubkeys.iter()
        .map(|s| parse_pubkey(s))
        .collect::<Result<_, _>>()?;
    let action = parse_timeout_action(&req.timeout_action)?;
    let gateway_id = req.gateway_id.as_deref().map(parse_pubkey).transpose()?;
    let buyer_pk = req.buyer_pubkey.as_deref().map(parse_pubkey).transpose()?;

    let escrow = state.client.get_first_module::<EscrowClientModule>()?;
    let result = escrow.module.receive_into_escrow(
        Amount::from_msats(req.amount_msats),
        seller_pk,
        oracle_pks,
        req.secret_code_hash,
        req.timeout_block,
        action,
        gateway_id,
        buyer_pk,
        req.description,
    ).await?;
    Ok(Json(result))
}

// ── POST /escrow/await-receive ─────────────────────────────────────────

#[derive(Deserialize)]
struct AwaitReceiveReq {
    operation_id: String,
    escrow_id: String,
    seller_pubkey: String,
    oracle_pubkeys: Vec<String>,
    amount_msats: u64,
    timeout_block: u32,
    timeout_action: String,
    secret_code_hash: String,
    timeout_secs: Option<u64>,
    buyer_pubkey: Option<String>,
}

async fn handle_await_receive(
    State(state): State<AppState>,
    Json(req): Json<AwaitReceiveReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let seller_pk = parse_pubkey(&req.seller_pubkey)?;
    let oracle_pks: Vec<PublicKey> = req.oracle_pubkeys.iter()
        .map(|s| parse_pubkey(s))
        .collect::<Result<_, _>>()?;
    let action = parse_timeout_action(&req.timeout_action)?;
    let buyer_pk = req.buyer_pubkey.as_deref().map(parse_pubkey).transpose()?;

    let escrow = state.client.get_first_module::<EscrowClientModule>()?;
    let result = escrow.module.await_receive_into_escrow(
        req.operation_id,
        req.escrow_id,
        Amount::from_msats(req.amount_msats),
        seller_pk,
        oracle_pks,
        req.secret_code_hash,
        req.timeout_block,
        action,
        req.timeout_secs.unwrap_or(5),
        buyer_pk,
    ).await?;
    Ok(Json(result))
}

// ── POST /escrow/claim-delegated-and-pay ───────────────────────────────

#[derive(Deserialize)]
struct ClaimDelegatedAndPayReq {
    escrow_id: String,
    secret_code: String,
    signature: String,
    bolt11: String,
}

async fn handle_claim_delegated_and_pay(
    State(state): State<AppState>,
    Json(req): Json<ClaimDelegatedAndPayReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let sig = parse_signature(&req.signature)?;
    let escrow = state.client.get_first_module::<EscrowClientModule>()?;
    let result = escrow.module.claim_delegated_and_pay(
        req.escrow_id,
        req.secret_code,
        sig,
        req.bolt11,
    ).await?;
    Ok(Json(result))
}

// ── POST /escrow/claim-timeout-delegated-and-pay ───────────────────────

#[derive(Deserialize)]
struct ClaimTimeoutDelegatedAndPayReq {
    escrow_id: String,
    signature: String,
    bolt11: String,
}

async fn handle_claim_timeout_delegated_and_pay(
    State(state): State<AppState>,
    Json(req): Json<ClaimTimeoutDelegatedAndPayReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let sig = parse_signature(&req.signature)?;
    let escrow = state.client.get_first_module::<EscrowClientModule>()?;
    let result = escrow.module.claim_timeout_delegated_and_pay(
        req.escrow_id,
        sig,
        req.bolt11,
    ).await?;
    Ok(Json(result))
}

// ── POST /escrow/dispute-delegated ─────────────────────────────────────

#[derive(Deserialize)]
struct DisputeDelegatedReq {
    escrow_id: String,
    disputer_pubkey: String,
    signature: String,
}

async fn handle_dispute_delegated(
    State(state): State<AppState>,
    Json(req): Json<DisputeDelegatedReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let disputer_pk = parse_pubkey(&req.disputer_pubkey)?;
    let sig = parse_signature(&req.signature)?;
    let escrow = state.client.get_first_module::<EscrowClientModule>()?;
    escrow.module.initiate_dispute_delegated(
        req.escrow_id,
        disputer_pk,
        sig,
    ).await?;
    Ok(Json(json!({})))
}

// ── POST /escrow/resolve-oracle ────────────────────────────────────────

#[derive(Deserialize)]
struct ResolveOracleReq {
    escrow_id: String,
    attestations: Vec<SignedAttestation>,
}

async fn handle_resolve_oracle(
    State(state): State<AppState>,
    Json(req): Json<ResolveOracleReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let escrow = state.client.get_first_module::<EscrowClientModule>()?;
    escrow.module.resolve_via_oracle(
        req.escrow_id,
        req.attestations,
    ).await?;
    Ok(Json(json!({})))
}

// ── POST /escrow/claim-and-pay (legacy) ────────────────────────────────

#[derive(Deserialize)]
struct ClaimAndPayReq {
    escrow_id: String,
    secret_code: String,
    bolt11: String,
}

async fn handle_claim_and_pay(
    State(state): State<AppState>,
    Json(req): Json<ClaimAndPayReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let escrow = state.client.get_first_module::<EscrowClientModule>()?;
    let result = escrow.module.claim_and_pay(
        req.escrow_id,
        req.secret_code,
        req.bolt11,
    ).await?;
    Ok(Json(result))
}

// ── POST /escrow/claim-timeout-and-pay (legacy) ────────────────────────

#[derive(Deserialize)]
struct ClaimTimeoutAndPayReq {
    escrow_id: String,
    bolt11: String,
}

async fn handle_claim_timeout_and_pay(
    State(state): State<AppState>,
    Json(req): Json<ClaimTimeoutAndPayReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let escrow = state.client.get_first_module::<EscrowClientModule>()?;
    let result = escrow.module.claim_timeout_and_pay(
        req.escrow_id,
        req.bolt11,
    ).await?;
    Ok(Json(result))
}

// ── POST /escrow/resolve-oracle-and-pay ──────────────────────────────

#[derive(Deserialize)]
struct ResolveOracleAndPayReq {
    escrow_id: String,
    attestations: Vec<SignedAttestation>,
    bolt11: String,
}

async fn handle_resolve_oracle_and_pay(
    State(state): State<AppState>,
    Json(req): Json<ResolveOracleAndPayReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let escrow = state.client.get_first_module::<EscrowClientModule>()?;
    // Step 1: resolve escrow via oracle attestations (e-cash lands in wallet)
    escrow.module.resolve_via_oracle(
        req.escrow_id.clone(),
        req.attestations,
    ).await?;
    // Step 2: immediately pay out via Lightning
    let result = escrow.module.pay_via_ln_module(req.bolt11).await?;
    Ok(Json(json!({
        "escrow_id": req.escrow_id,
        "payment": result,
    })))
}

// ── POST /escrow/await-invoice ─────────────────────────────────────────

#[derive(Deserialize)]
struct AwaitInvoiceReq {
    operation_id: String,
    timeout_secs: Option<u64>,
}

async fn handle_await_invoice(
    State(state): State<AppState>,
    Json(req): Json<AwaitInvoiceReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let op_id: fedimint_core::core::OperationId = req.operation_id
        .parse()
        .map_err(|e| ApiError(anyhow::anyhow!("Invalid operation_id: {e}")))?;

    let timeout_secs = req.timeout_secs.unwrap_or(2);

    // Access LN module
    let ln_inst = state.client.get_first_module::<LightningClientModule>()?;
    let ln = ln_inst.module;

    // Subscribe and wait briefly
    let mut updates = ln.subscribe_ln_receive(op_id).await?.into_stream();
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(Json(json!({"status": "awaiting"})));
        }
        match tokio::time::timeout(remaining, updates.next()).await {
            Ok(Some(LnReceiveState::Claimed)) => {
                return Ok(Json(json!({"status": "paid"})));
            }
            Ok(Some(LnReceiveState::Canceled { reason })) => {
                return Ok(Json(json!({"status": "failed", "reason": format!("{reason:?}")})));
            }
            Ok(Some(_)) => continue,
            Ok(None) => return Ok(Json(json!({"status": "awaiting"}))),
            Err(_) => return Ok(Json(json!({"status": "awaiting"}))),
        }
    }
}

// ── Error type ─────────────────────────────────────────────────────────

struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response<Body> {
        tracing::debug!("ApiError: {}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
