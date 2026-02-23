use fedimint_core::BitcoinHash; // needed for TransactionId::all_zeros()
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::Amounts;
use fedimint_core::{Amount, InPoint, OutPoint, TransactionId};
use fedimint_escrow_common::oracle::{
    attestation_signing_bytes, Beneficiary, OracleAttestationContent, SignedAttestation,
};
use fedimint_escrow_common::{
    EscrowInput, EscrowInputClamingWithoutDispute, EscrowInputDisputing,
    EscrowInputOracleAttestation, EscrowInputTimeoutClaim, EscrowOutput, EscrowOutputError,
    EscrowStates, TimeoutAction, hash256,
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

/// Build a standard EscrowOutput with 3 oracle keypairs
fn make_output(
    amount: Amount,
    buyer_kp: &Keypair,
    seller_kp: &Keypair,
    oracle_kps: &[&Keypair; 3],
    escrow_id: &str,
    secret: &str,
    timeout_block: u32,
    timeout_action: TimeoutAction,
) -> EscrowOutput {
    EscrowOutput {
        amount,
        buyer_pubkey: buyer_kp.public_key(),
        seller_pubkey: seller_kp.public_key(),
        oracle_pubkeys: vec![
            oracle_kps[0].public_key(),
            oracle_kps[1].public_key(),
            oracle_kps[2].public_key(),
        ],
        escrow_id: escrow_id.to_string(),
        secret_code_hash: hash256(secret.to_string()),
        timeout_block,
        timeout_action,
    }
}

/// Sign a 32-byte message with a keypair (Schnorr)
fn sign(kp: &Keypair, msg_bytes: &[u8; 32]) -> secp256k1::schnorr::Signature {
    let secp = Secp256k1::new();
    let message = Message::from_digest_slice(msg_bytes).expect("32 bytes");
    secp.sign_schnorr(&message, kp)
}

/// Build a signed oracle attestation for testing
fn make_attestation(oracle_kp: &Keypair, escrow_id: &str, outcome: Beneficiary) -> SignedAttestation {
    let content = OracleAttestationContent {
        escrow_id: escrow_id.to_string(),
        outcome,
        decided_at: 1_000_000,
        reason: None,
    };
    let secp = Secp256k1::new();
    let msg_bytes = attestation_signing_bytes(&content, &oracle_kp.public_key());
    let message = Message::from_digest_slice(&msg_bytes).expect("32 bytes");
    let signature = secp.sign_schnorr(&message, oracle_kp);
    SignedAttestation {
        pubkey: oracle_kp.public_key(),
        signature,
        content,
    }
}

// ─── process_output tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_escrow_stores_value() {
    let escrow = test_escrow();
    let db = test_db().await;
    let secp = Secp256k1::new();
    let buyer_kp = Keypair::new(&secp, &mut OsRng);
    let seller_kp = Keypair::new(&secp, &mut OsRng);
    let oracle_kp1 = Keypair::new(&secp, &mut OsRng);
    let oracle_kp2 = Keypair::new(&secp, &mut OsRng);
    let oracle_kp3 = Keypair::new(&secp, &mut OsRng);

    let output = make_output(
        Amount::from_sats(10_000),
        &buyer_kp,
        &seller_kp,
        &[&oracle_kp1, &oracle_kp2, &oracle_kp3],
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
    assert_eq!(v.oracle_pubkeys[0], oracle_kp1.public_key());
    assert_eq!(v.oracle_pubkeys.len(), 3);
    dbtx.commit_tx().await;
}

#[tokio::test]
async fn test_duplicate_escrow_id_rejected() {
    let escrow = test_escrow();
    let db = test_db().await;
    let secp = Secp256k1::new();
    let buyer_kp = Keypair::new(&secp, &mut OsRng);
    let seller_kp = Keypair::new(&secp, &mut OsRng);
    let oracle_kp1 = Keypair::new(&secp, &mut OsRng);
    let oracle_kp2 = Keypair::new(&secp, &mut OsRng);
    let oracle_kp3 = Keypair::new(&secp, &mut OsRng);

    let output = make_output(
        Amount::from_sats(5_000),
        &buyer_kp,
        &seller_kp,
        &[&oracle_kp1, &oracle_kp2, &oracle_kp3],
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
) -> (Database, Keypair, Keypair, [Keypair; 3]) {
    let db = test_db().await;
    let secp = Secp256k1::new();
    let buyer_kp = Keypair::new(&secp, &mut OsRng);
    let seller_kp = Keypair::new(&secp, &mut OsRng);
    let oracle_kp1 = Keypair::new(&secp, &mut OsRng);
    let oracle_kp2 = Keypair::new(&secp, &mut OsRng);
    let oracle_kp3 = Keypair::new(&secp, &mut OsRng);

    let output = make_output(
        amount,
        &buyer_kp,
        &seller_kp,
        &[&oracle_kp1, &oracle_kp2, &oracle_kp3],
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

    (db, buyer_kp, seller_kp, [oracle_kp1, oracle_kp2, oracle_kp3])
}

/// Put an escrow into DisputedByBuyer state
async fn dispute_escrow(escrow: &Escrow, db: &Database, escrow_id: &str, disputer_kp: &Keypair) {
    let msg = [10u8; 32];
    let sig = sign(disputer_kp, &msg);
    let input = EscrowInput::Disputing(EscrowInputDisputing {
        escrow_id: escrow_id.to_string(),
        disputer: disputer_kp.public_key(),
        hashed_message: msg,
        signature: sig,
    });
    let mut dbtx = db.begin_transaction().await;
    escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await
        .unwrap();
    dbtx.commit_tx().await;
}

// ─── TimeoutClaim tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_timeout_claim_before_expiry_rejected() {
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, _oracle_kps) = setup_escrow_for_input(
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
    let (db, buyer_kp, _seller_kp, _oracle_kps) = setup_escrow_for_input(
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
    let (db, _buyer_kp, seller_kp, _oracle_kps) = setup_escrow_for_input(
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
    let (db, _buyer_kp, seller_kp, _oracle_kps) = setup_escrow_for_input(
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
    let (db, buyer_kp, _seller_kp, _oracle_kps) = setup_escrow_for_input(
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

    // Create 3 escrows of 10_000 sats each → total liability = 30_000 sats
    for i in 0..3u8 {
        let buyer_kp = Keypair::new(&secp, &mut OsRng);
        let seller_kp = Keypair::new(&secp, &mut OsRng);
        let oracle_kp1 = Keypair::new(&secp, &mut OsRng);
        let oracle_kp2 = Keypair::new(&secp, &mut OsRng);
        let oracle_kp3 = Keypair::new(&secp, &mut OsRng);
        let output = make_output(
            Amount::from_sats(10_000),
            &buyer_kp,
            &seller_kp,
            &[&oracle_kp1, &oracle_kp2, &oracle_kp3],
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

// ─── Cooperative claim (regression test) ─────────────────────────────────────

#[tokio::test]
async fn test_cooperative_claim_without_dispute() {
    let escrow = test_escrow();
    let (db, _buyer_kp, seller_kp, _oracle_kps) = setup_escrow_for_input(
        &escrow,
        "coop-claim",
        Amount::from_sats(5_000),
        999,
        TimeoutAction::Refund,
    )
    .await;

    let secret = "secret123";
    let msg = [42u8; 32];
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

// ─── Oracle attestation tests ─────────────────────────────────────────────────

#[tokio::test]
async fn test_oracle_two_sigs_buyer_wins() {
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, oracle_kps) = setup_escrow_for_input(
        &escrow,
        "oracle-buyer-wins",
        Amount::from_sats(10_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    // Put escrow into disputed state
    dispute_escrow(&escrow, &db, "oracle-buyer-wins", &buyer_kp).await;

    // Two oracle attestations: buyer wins
    let att1 = make_attestation(&oracle_kps[0], "oracle-buyer-wins", Beneficiary::Buyer);
    let att2 = make_attestation(&oracle_kps[1], "oracle-buyer-wins", Beneficiary::Buyer);

    let input = EscrowInput::OracleAttestation(EscrowInputOracleAttestation {
        amount: Amount::from_sats(10_000),
        escrow_id: "oracle-buyer-wins".to_string(),
        attestations: vec![att1, att2],
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_ok(), "Two valid oracle sigs should pass: {:?}", result.err());
    let meta = result.unwrap();
    assert_eq!(meta.pub_key, buyer_kp.public_key(), "Buyer should win");
    assert_eq!(meta.amount.amounts, Amounts::new_bitcoin(Amount::from_sats(10_000)));
}

#[tokio::test]
async fn test_oracle_two_sigs_seller_wins() {
    let escrow = test_escrow();
    let (db, buyer_kp, seller_kp, oracle_kps) = setup_escrow_for_input(
        &escrow,
        "oracle-seller-wins",
        Amount::from_sats(10_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    dispute_escrow(&escrow, &db, "oracle-seller-wins", &buyer_kp).await;

    let att1 = make_attestation(&oracle_kps[0], "oracle-seller-wins", Beneficiary::Seller);
    let att2 = make_attestation(&oracle_kps[2], "oracle-seller-wins", Beneficiary::Seller);

    let input = EscrowInput::OracleAttestation(EscrowInputOracleAttestation {
        amount: Amount::from_sats(10_000),
        escrow_id: "oracle-seller-wins".to_string(),
        attestations: vec![att1, att2],
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_ok(), "Two valid oracle sigs for seller should pass: {:?}", result.err());
    let meta = result.unwrap();
    assert_eq!(meta.pub_key, seller_kp.public_key(), "Seller should win");
}

#[tokio::test]
async fn test_oracle_single_sig_threshold_fails() {
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, oracle_kps) = setup_escrow_for_input(
        &escrow,
        "oracle-single-sig",
        Amount::from_sats(10_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    dispute_escrow(&escrow, &db, "oracle-single-sig", &buyer_kp).await;

    // Only ONE attestation — threshold not met
    let att1 = make_attestation(&oracle_kps[0], "oracle-single-sig", Beneficiary::Buyer);

    let input = EscrowInput::OracleAttestation(EscrowInputOracleAttestation {
        amount: Amount::from_sats(10_000),
        escrow_id: "oracle-single-sig".to_string(),
        attestations: vec![att1],
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Single oracle sig should fail");
    assert!(
        matches!(
            result.unwrap_err(),
            fedimint_escrow_common::EscrowInputError::OracleThresholdNotMet
        ),
        "Expected OracleThresholdNotMet"
    );
}

#[tokio::test]
async fn test_oracle_conflicting_outcomes_rejected() {
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, oracle_kps) = setup_escrow_for_input(
        &escrow,
        "oracle-conflict",
        Amount::from_sats(10_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    dispute_escrow(&escrow, &db, "oracle-conflict", &buyer_kp).await;

    // Two attestations with DIFFERENT outcomes
    let att1 = make_attestation(&oracle_kps[0], "oracle-conflict", Beneficiary::Buyer);
    let att2 = make_attestation(&oracle_kps[1], "oracle-conflict", Beneficiary::Seller);

    let input = EscrowInput::OracleAttestation(EscrowInputOracleAttestation {
        amount: Amount::from_sats(10_000),
        escrow_id: "oracle-conflict".to_string(),
        attestations: vec![att1, att2],
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Conflicting outcomes should be rejected");
    assert!(
        matches!(
            result.unwrap_err(),
            fedimint_escrow_common::EscrowInputError::ConflictingOracleOutcomes
        ),
        "Expected ConflictingOracleOutcomes"
    );
}

#[tokio::test]
async fn test_oracle_unknown_pubkey_rejected() {
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, _oracle_kps) = setup_escrow_for_input(
        &escrow,
        "oracle-unknown-key",
        Amount::from_sats(10_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    dispute_escrow(&escrow, &db, "oracle-unknown-key", &buyer_kp).await;

    // Use completely different keypairs (not in the registered set)
    let secp = Secp256k1::new();
    let unknown_kp1 = Keypair::new(&secp, &mut OsRng);
    let unknown_kp2 = Keypair::new(&secp, &mut OsRng);
    let att1 = make_attestation(&unknown_kp1, "oracle-unknown-key", Beneficiary::Buyer);
    let att2 = make_attestation(&unknown_kp2, "oracle-unknown-key", Beneficiary::Buyer);

    let input = EscrowInput::OracleAttestation(EscrowInputOracleAttestation {
        amount: Amount::from_sats(10_000),
        escrow_id: "oracle-unknown-key".to_string(),
        attestations: vec![att1, att2],
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Unknown oracle pubkeys should be rejected");
    assert!(
        matches!(
            result.unwrap_err(),
            fedimint_escrow_common::EscrowInputError::UnknownOracle
        ),
        "Expected UnknownOracle"
    );
}

#[tokio::test]
async fn test_oracle_wrong_escrow_id_rejected() {
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, oracle_kps) = setup_escrow_for_input(
        &escrow,
        "oracle-wrong-id",
        Amount::from_sats(10_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    dispute_escrow(&escrow, &db, "oracle-wrong-id", &buyer_kp).await;

    // Attestations signed for a DIFFERENT escrow_id
    let att1 = make_attestation(&oracle_kps[0], "other-escrow-id", Beneficiary::Buyer);
    let att2 = make_attestation(&oracle_kps[1], "other-escrow-id", Beneficiary::Buyer);

    let input = EscrowInput::OracleAttestation(EscrowInputOracleAttestation {
        amount: Amount::from_sats(10_000),
        escrow_id: "oracle-wrong-id".to_string(),
        attestations: vec![att1, att2],
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Wrong escrow_id should be rejected");
    assert!(
        matches!(
            result.unwrap_err(),
            fedimint_escrow_common::EscrowInputError::EscrowIdMismatch
        ),
        "Expected EscrowIdMismatch"
    );
}

#[tokio::test]
async fn test_oracle_duplicate_pubkey_counts_once() {
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, oracle_kps) = setup_escrow_for_input(
        &escrow,
        "oracle-dup-pubkey",
        Amount::from_sats(10_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    dispute_escrow(&escrow, &db, "oracle-dup-pubkey", &buyer_kp).await;

    // Same oracle signs twice — should only count as 1 vote (threshold not met)
    let att1 = make_attestation(&oracle_kps[0], "oracle-dup-pubkey", Beneficiary::Buyer);
    let att2 = make_attestation(&oracle_kps[0], "oracle-dup-pubkey", Beneficiary::Buyer);

    let input = EscrowInput::OracleAttestation(EscrowInputOracleAttestation {
        amount: Amount::from_sats(10_000),
        escrow_id: "oracle-dup-pubkey".to_string(),
        attestations: vec![att1, att2],
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Duplicate oracle pubkey should not meet threshold");
    assert!(
        matches!(
            result.unwrap_err(),
            fedimint_escrow_common::EscrowInputError::OracleThresholdNotMet
        ),
        "Expected OracleThresholdNotMet"
    );
}

#[tokio::test]
async fn test_oracle_non_disputed_state_rejected() {
    let escrow = test_escrow();
    let (db, _buyer_kp, _seller_kp, oracle_kps) = setup_escrow_for_input(
        &escrow,
        "oracle-not-disputed",
        Amount::from_sats(10_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    // Do NOT dispute — escrow is still Open
    let att1 = make_attestation(&oracle_kps[0], "oracle-not-disputed", Beneficiary::Buyer);
    let att2 = make_attestation(&oracle_kps[1], "oracle-not-disputed", Beneficiary::Buyer);

    let input = EscrowInput::OracleAttestation(EscrowInputOracleAttestation {
        amount: Amount::from_sats(10_000),
        escrow_id: "oracle-not-disputed".to_string(),
        attestations: vec![att1, att2],
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Oracle resolution on non-disputed escrow should fail");
    assert!(
        matches!(
            result.unwrap_err(),
            fedimint_escrow_common::EscrowInputError::InvalidStateForClaimingEscrow
        ),
        "Expected InvalidStateForClaimingEscrow"
    );
}
