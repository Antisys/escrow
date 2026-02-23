use fedimint_core::BitcoinHash; // needed for TransactionId::all_zeros()
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::Amounts;
use fedimint_core::{Amount, InPoint, OutPoint, TransactionId};
use fedimint_escrow_common::{
    EscrowInput, EscrowInputClamingWithoutDispute, EscrowInputTimeoutClaim, EscrowOutput,
    EscrowOutputError, EscrowStates, TimeoutAction, hash256,
};
use fedimint_server_core::ServerModule;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Keypair, Message, Secp256k1};

use crate::db::{BlockHeightKey, EscrowKey};
use crate::{Escrow, EscrowValue};
use fedimint_escrow_common::config::{EscrowConfig, EscrowConfigConsensus, EscrowConfigPrivate};

/// Build a test Escrow module instance
fn test_escrow() -> Escrow {
    Escrow::new(EscrowConfig {
        private: EscrowConfigPrivate,
        consensus: EscrowConfigConsensus {
            deposit_fee: Amount::ZERO,
            max_arbiter_fee_bps: 1000,
        },
    })
}

/// Build an in-memory Fedimint Database
async fn test_db() -> Database {
    Database::new(MemDatabase::new(), Default::default())
}

/// Dummy InPoint (not meaningful for our logic)
fn dummy_in_point() -> InPoint {
    InPoint {
        txid: TransactionId::all_zeros(),
        in_idx: 0,
    }
}

/// Dummy OutPoint
fn dummy_out_point() -> OutPoint {
    OutPoint {
        txid: TransactionId::all_zeros(),
        out_idx: 0,
    }
}

/// Build a standard EscrowOutput with caller-supplied keys
fn make_output(
    amount: Amount,
    buyer_kp: &Keypair,
    seller_kp: &Keypair,
    arbiter_kp: &Keypair,
    escrow_id: &str,
    secret: &str,
    timeout_block: u32,
    timeout_action: TimeoutAction,
) -> EscrowOutput {
    EscrowOutput {
        amount,
        buyer_pubkey: buyer_kp.public_key(),
        seller_pubkey: seller_kp.public_key(),
        arbiter_pubkey: arbiter_kp.public_key(),
        escrow_id: escrow_id.to_string(),
        secret_code_hash: hash256(secret.to_string()),
        max_arbiter_fee: Amount::from_sats(1000),
        timeout_block,
        timeout_action,
    }
}

/// Sign a 32-byte message with a keypair
fn sign(kp: &Keypair, msg_bytes: &[u8; 32]) -> secp256k1::schnorr::Signature {
    let secp = Secp256k1::new();
    let message = Message::from_digest_slice(msg_bytes).expect("32 bytes");
    secp.sign_schnorr(&message, kp)
}

// ─── process_output tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_escrow_stores_value() {
    let escrow = test_escrow();
    let db = test_db().await;
    let secp = Secp256k1::new();
    let buyer_kp = Keypair::new(&secp, &mut OsRng);
    let seller_kp = Keypair::new(&secp, &mut OsRng);
    let arbiter_kp = Keypair::new(&secp, &mut OsRng);

    let output = make_output(
        Amount::from_sats(10_000),
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        "escrow-1",
        "secret",
        1000,
        TimeoutAction::Refund,
    );

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_output(&mut dbtx.to_ref_nc(), &output, dummy_out_point())
        .await;
    assert!(result.is_ok(), "process_output failed: {:?}", result.err());
    let amounts = result.unwrap();
    assert_eq!(amounts.amounts, Amounts::new_bitcoin(Amount::from_sats(10_000)));

    let stored: Option<EscrowValue> = dbtx
        .get_value(&EscrowKey { escrow_id: "escrow-1".to_string() })
        .await;
    assert!(stored.is_some(), "EscrowValue should be stored in DB");
    let v = stored.unwrap();
    assert_eq!(v.state, EscrowStates::Open);
    assert_eq!(v.timeout_block, 1000);
    assert_eq!(v.timeout_action, TimeoutAction::Refund);
    dbtx.commit_tx().await;
}

#[tokio::test]
async fn test_duplicate_escrow_id_rejected() {
    let escrow = test_escrow();
    let db = test_db().await;
    let secp = Secp256k1::new();
    let buyer_kp = Keypair::new(&secp, &mut OsRng);
    let seller_kp = Keypair::new(&secp, &mut OsRng);
    let arbiter_kp = Keypair::new(&secp, &mut OsRng);

    let output = make_output(
        Amount::from_sats(5_000),
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        "dup-escrow",
        "secret",
        500,
        TimeoutAction::Release,
    );

    let mut dbtx = db.begin_transaction().await;
    escrow
        .process_output(&mut dbtx.to_ref_nc(), &output, dummy_out_point())
        .await
        .unwrap();
    dbtx.commit_tx().await;

    let mut dbtx2 = db.begin_transaction().await;
    let result = escrow
        .process_output(&mut dbtx2.to_ref_nc(), &output, dummy_out_point())
        .await;
    assert_eq!(result.unwrap_err(), EscrowOutputError::EscrowAlreadyExists);
    dbtx2.commit_tx().await;
}

// ─── Helper: create an escrow ready for input tests ──────────────────────────

async fn setup_escrow_for_input(
    escrow: &Escrow,
    escrow_id: &str,
    amount: Amount,
    timeout_block: u32,
    timeout_action: TimeoutAction,
) -> (Database, Keypair, Keypair, Keypair) {
    let db = test_db().await;
    let secp = Secp256k1::new();
    let buyer_kp = Keypair::new(&secp, &mut OsRng);
    let seller_kp = Keypair::new(&secp, &mut OsRng);
    let arbiter_kp = Keypair::new(&secp, &mut OsRng);

    let output = make_output(
        amount,
        &buyer_kp,
        &seller_kp,
        &arbiter_kp,
        escrow_id,
        "secret123",
        timeout_block,
        timeout_action,
    );

    let mut dbtx = db.begin_transaction().await;
    escrow
        .process_output(&mut dbtx.to_ref_nc(), &output, dummy_out_point())
        .await
        .unwrap();
    dbtx.commit_tx().await;

    (db, buyer_kp, seller_kp, arbiter_kp)
}

// ─── TimeoutClaim tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_timeout_claim_before_expiry_rejected() {
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, _arbiter_kp) = setup_escrow_for_input(
        &escrow,
        "timeout-early",
        Amount::from_sats(10_000),
        1000,
        TimeoutAction::Refund,
    )
    .await;

    let msg = [0u8; 32];
    let sig = sign(&buyer_kp, &msg);

    let input = EscrowInput::TimeoutClaim(EscrowInputTimeoutClaim {
        amount: Amount::from_sats(10_000),
        escrow_id: "timeout-early".to_string(),
        hashed_message: msg,
        signature: sig,
    });

    let mut dbtx = db.begin_transaction().await;
    // Block height BELOW timeout_block (500 < 1000)
    dbtx.insert_entry(&BlockHeightKey, &500u64).await;

    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Should fail: timelock not yet expired");
    assert!(
        matches!(
            result.unwrap_err(),
            fedimint_escrow_common::EscrowInputError::TimelockNotExpired { current: 500, required: 1000 }
        ),
        "Expected TimelockNotExpired"
    );
}

#[tokio::test]
async fn test_timeout_claim_after_expiry_refund_action_buyer_succeeds() {
    let escrow = test_escrow();
    // timeout_action = Refund → buyer gets the funds after timeout
    let (db, buyer_kp, _seller_kp, _arbiter_kp) = setup_escrow_for_input(
        &escrow,
        "timeout-refund",
        Amount::from_sats(10_000),
        1000,
        TimeoutAction::Refund,
    )
    .await;

    let msg = [1u8; 32];
    let sig = sign(&buyer_kp, &msg);

    let input = EscrowInput::TimeoutClaim(EscrowInputTimeoutClaim {
        amount: Amount::from_sats(10_000),
        escrow_id: "timeout-refund".to_string(),
        hashed_message: msg,
        signature: sig,
    });

    let mut dbtx = db.begin_transaction().await;
    // Block height ABOVE timeout_block (1500 >= 1000)
    dbtx.insert_entry(&BlockHeightKey, &1500u64).await;

    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_ok(), "Should succeed: timelock expired, buyer key. err={:?}", result.err());
    let meta = result.unwrap();
    assert_eq!(meta.amount.amounts, Amounts::new_bitcoin(Amount::from_sats(10_000)));
    assert_eq!(meta.pub_key, buyer_kp.public_key());
}

#[tokio::test]
async fn test_timeout_claim_release_action_seller_succeeds() {
    let escrow = test_escrow();
    // timeout_action = Release → seller gets the funds after timeout
    let (db, _buyer_kp, seller_kp, _arbiter_kp) = setup_escrow_for_input(
        &escrow,
        "timeout-release",
        Amount::from_sats(20_000),
        500,
        TimeoutAction::Release,
    )
    .await;

    let msg = [2u8; 32];
    let sig = sign(&seller_kp, &msg);

    let input = EscrowInput::TimeoutClaim(EscrowInputTimeoutClaim {
        amount: Amount::from_sats(20_000),
        escrow_id: "timeout-release".to_string(),
        hashed_message: msg,
        signature: sig,
    });

    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&BlockHeightKey, &600u64).await;

    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_ok(), "Should succeed: Release timeout, seller sig. err={:?}", result.err());
    let meta = result.unwrap();
    assert_eq!(meta.pub_key, seller_kp.public_key());
}

#[tokio::test]
async fn test_timeout_claim_wrong_key_rejected() {
    let escrow = test_escrow();
    // timeout_action = Refund → buyer must sign; attempt with seller key (wrong)
    let (db, _buyer_kp, seller_kp, _arbiter_kp) = setup_escrow_for_input(
        &escrow,
        "timeout-wrong-key",
        Amount::from_sats(10_000),
        1000,
        TimeoutAction::Refund,
    )
    .await;

    let msg = [3u8; 32];
    let sig = sign(&seller_kp, &msg); // Wrong key: should be buyer_kp

    let input = EscrowInput::TimeoutClaim(EscrowInputTimeoutClaim {
        amount: Amount::from_sats(10_000),
        escrow_id: "timeout-wrong-key".to_string(),
        hashed_message: msg,
        signature: sig,
    });

    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&BlockHeightKey, &1500u64).await;

    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Should fail: wrong signing key");
    assert!(
        matches!(result.unwrap_err(), fedimint_escrow_common::EscrowInputError::InvalidBuyer),
        "Expected InvalidBuyer"
    );
}

#[tokio::test]
async fn test_timeout_block_height_unknown_rejected() {
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, _arbiter_kp) = setup_escrow_for_input(
        &escrow,
        "timeout-no-height",
        Amount::from_sats(10_000),
        1000,
        TimeoutAction::Refund,
    )
    .await;

    let msg = [4u8; 32];
    let sig = sign(&buyer_kp, &msg);

    let input = EscrowInput::TimeoutClaim(EscrowInputTimeoutClaim {
        amount: Amount::from_sats(10_000),
        escrow_id: "timeout-no-height".to_string(),
        hashed_message: msg,
        signature: sig,
    });

    // BlockHeightKey is NOT set → should return BlockHeightUnknown
    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), fedimint_escrow_common::EscrowInputError::BlockHeightUnknown),
        "Expected BlockHeightUnknown"
    );
}

// ─── Audit tests ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_audit_balance() {
    use fedimint_core::core::ModuleInstanceId;
    use fedimint_core::module::audit::Audit;

    let escrow = test_escrow();
    let db = test_db().await;
    let secp = Secp256k1::new();

    // Create 3 escrows of 10_000 sats each → total liability = 30_000 sats = 30_000_000 msat
    for i in 0..3u8 {
        let buyer_kp = Keypair::new(&secp, &mut OsRng);
        let seller_kp = Keypair::new(&secp, &mut OsRng);
        let arbiter_kp = Keypair::new(&secp, &mut OsRng);
        let output = make_output(
            Amount::from_sats(10_000),
            &buyer_kp,
            &seller_kp,
            &arbiter_kp,
            &format!("audit-escrow-{i}"),
            "secret",
            9999,
            TimeoutAction::Refund,
        );
        let mut dbtx = db.begin_transaction().await;
        escrow
            .process_output(&mut dbtx.to_ref_nc(), &output, dummy_out_point())
            .await
            .unwrap();
        dbtx.commit_tx().await;
    }

    // Audit: should report -30_000_000 msat (all 3 are open = liabilities)
    let mut dbtx = db.begin_transaction().await;
    let mut audit = Audit::default();
    escrow
        .audit(&mut dbtx.to_ref_nc(), &mut audit, ModuleInstanceId::from(0u16))
        .await;
    dbtx.commit_tx().await;

    let net = audit.net_assets().map(|a| a.milli_sat).unwrap_or(0);
    assert_eq!(net, -(30_000i64 * 1000), "All 3 open: liability = 30_000 sats");

    // Mark one escrow as TimedOut (no more liability for it)
    {
        let mut dbtx = db.begin_transaction().await;
        let key = EscrowKey { escrow_id: "audit-escrow-0".to_string() };
        let mut v: EscrowValue = dbtx.get_value(&key).await.unwrap();
        v.state = EscrowStates::TimedOut;
        dbtx.insert_entry(&key, &v).await;
        dbtx.commit_tx().await;
    }

    // Audit: should now report -20_000_000 msat (2 open remain)
    let mut dbtx = db.begin_transaction().await;
    let mut audit2 = Audit::default();
    escrow
        .audit(&mut dbtx.to_ref_nc(), &mut audit2, ModuleInstanceId::from(0u16))
        .await;
    dbtx.commit_tx().await;

    let net2 = audit2.net_assets().map(|a| a.milli_sat).unwrap_or(0);
    assert_eq!(net2, -(20_000i64 * 1000), "After timed-out: liability = 20_000 sats");
}

// ─── Existing path: cooperative claim (regression test) ──────────────────────

#[tokio::test]
async fn test_cooperative_claim_without_dispute() {
    let escrow = test_escrow();
    let (db, _buyer_kp, seller_kp, _arbiter_kp) = setup_escrow_for_input(
        &escrow,
        "coop-claim",
        Amount::from_sats(5_000),
        999,
        TimeoutAction::Refund,
    )
    .await;

    // seller signs with a hashed message; secret code must match hash in DB
    let secret = "secret123";
    let msg = [42u8; 32]; // arbitrary 32-byte message for the signature
    let sig = sign(&seller_kp, &msg);

    let input = EscrowInput::ClamingWithoutDispute(EscrowInputClamingWithoutDispute {
        amount: Amount::from_sats(5_000),
        escrow_id: "coop-claim".to_string(),
        secret_code: secret.to_string(),
        hashed_message: msg,
        signature: sig,
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_ok(), "Cooperative claim should succeed. err={:?}", result.err());
    let meta = result.unwrap();
    assert_eq!(meta.pub_key, seller_kp.public_key());
}
