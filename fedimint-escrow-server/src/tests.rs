use fedimint_core::BitcoinHash; // needed for TransactionId::all_zeros()
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::Amounts;
use fedimint_core::{Amount, InPoint, OutPoint, TransactionId};
use fedimint_escrow_common::oracle::{
    attestation_signing_bytes, Beneficiary, OracleAttestationContent, SignedAttestation,
};
use fedimint_escrow_common::{
    EscrowInput, EscrowInputClamingWithoutDispute, EscrowInputClaimDelegated,
    EscrowInputDisputing, EscrowInputDisputeDelegated,
    EscrowInputOracleAttestation, EscrowInputTimeoutClaim, EscrowInputTimeoutClaimDelegated,
    EscrowOutput, EscrowOutputError, EscrowStates, TimeoutAction, hash256,
};
use fedimint_server_core::ServerModule;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Keypair, Message, Secp256k1};

use crate::db::{BlockHeightKey, EscrowKey};
use crate::{Escrow, EscrowValue};
use fedimint_escrow_common::config::{EscrowConfig, EscrowConfigConsensus, EscrowConfigPrivate};
use sha2::{Sha256, Digest};

/// Compute SHA256 of a string as [u8; 32] (for hashed_message fields)
fn sha256_bytes(input: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

/// Build a test Escrow module instance
fn test_escrow() -> Escrow {
    Escrow::new_for_testing(EscrowConfig {
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

/// Generate a random service keypair (simulates the service submitting oracle resolution)
fn random_service_kp() -> Keypair {
    let secp = Secp256k1::new();
    Keypair::new(&secp, &mut OsRng)
}

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
    let service_kp = random_service_kp();

    let input = EscrowInput::OracleAttestation(EscrowInputOracleAttestation {
        amount: Amount::from_sats(10_000),
        escrow_id: "oracle-buyer-wins".to_string(),
        attestations: vec![att1, att2],
        submitter_pubkey: service_kp.public_key(),
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_ok(), "Two valid oracle sigs should pass: {:?}", result.err());
    let meta = result.unwrap();
    assert_eq!(meta.pub_key, service_kp.public_key(), "E-cash goes to submitter (service)");
    assert_eq!(meta.amount.amounts, Amounts::new_bitcoin(Amount::from_sats(10_000)));
}

#[tokio::test]
async fn test_oracle_two_sigs_seller_wins() {
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, oracle_kps) = setup_escrow_for_input(
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
    let service_kp = random_service_kp();

    let input = EscrowInput::OracleAttestation(EscrowInputOracleAttestation {
        amount: Amount::from_sats(10_000),
        escrow_id: "oracle-seller-wins".to_string(),
        attestations: vec![att1, att2],
        submitter_pubkey: service_kp.public_key(),
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_ok(), "Two valid oracle sigs for seller should pass: {:?}", result.err());
    let meta = result.unwrap();
    assert_eq!(meta.pub_key, service_kp.public_key(), "E-cash goes to submitter (service)");
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
        submitter_pubkey: random_service_kp().public_key(),
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
        submitter_pubkey: random_service_kp().public_key(),
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
        submitter_pubkey: random_service_kp().public_key(),
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
        submitter_pubkey: random_service_kp().public_key(),
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
        submitter_pubkey: random_service_kp().public_key(),
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

// ─── Security tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_double_spend_rejected() {
    // Claim an escrow successfully, then try to claim it again — must fail
    let escrow = test_escrow();
    let (db, _buyer_kp, seller_kp, _oracle_kps) = setup_escrow_for_input(
        &escrow,
        "double-spend",
        Amount::from_sats(5_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    let secret = "secret123";
    let msg = [99u8; 32];
    let sig = sign(&seller_kp, &msg);

    let input = EscrowInput::ClamingWithoutDispute(EscrowInputClamingWithoutDispute {
        amount: Amount::from_sats(5_000),
        escrow_id: "double-spend".to_string(),
        secret_code: secret.to_string(),
        hashed_message: msg,
        signature: sig.clone(),
    });

    // First claim: should succeed
    let mut dbtx = db.begin_transaction().await;
    let result1 = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;
    assert!(result1.is_ok(), "First claim should succeed: {:?}", result1.err());

    // Second claim: must be rejected — escrow is no longer Open
    let input2 = EscrowInput::ClamingWithoutDispute(EscrowInputClamingWithoutDispute {
        amount: Amount::from_sats(5_000),
        escrow_id: "double-spend".to_string(),
        secret_code: secret.to_string(),
        hashed_message: msg,
        signature: sig,
    });
    let mut dbtx2 = db.begin_transaction().await;
    let result2 = escrow
        .process_input(&mut dbtx2.to_ref_nc(), &input2, dummy_in_point())
        .await;
    dbtx2.commit_tx().await;
    assert!(result2.is_err(), "Double-spend must be rejected");
    assert!(
        matches!(
            result2.unwrap_err(),
            fedimint_escrow_common::EscrowInputError::InvalidStateForClaimingEscrow
        ),
        "Expected InvalidStateForClaimingEscrow on second claim"
    );
}

#[tokio::test]
async fn test_forged_signature_rejected() {
    // Valid seller key in the input, but the signature bytes are all-zeros (forged)
    let escrow = test_escrow();
    let (db, _buyer_kp, seller_kp, _oracle_kps) = setup_escrow_for_input(
        &escrow,
        "forged-sig",
        Amount::from_sats(5_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    let msg = [77u8; 32];
    // Build a valid-looking Schnorr signature over a *different* message, so the
    // bytes are a real signature but not over the claimed hashed_message.
    let secp = Secp256k1::new();
    let different_msg = [88u8; 32];
    let wrong_sig = secp.sign_schnorr(
        &secp256k1::Message::from_digest_slice(&different_msg).unwrap(),
        &seller_kp,
    );

    let input = EscrowInput::ClamingWithoutDispute(EscrowInputClamingWithoutDispute {
        amount: Amount::from_sats(5_000),
        escrow_id: "forged-sig".to_string(),
        secret_code: "secret123".to_string(),
        hashed_message: msg,      // claimed message
        signature: wrong_sig,     // signed over different_msg ≠ msg
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Forged signature must be rejected");
    assert!(
        matches!(
            result.unwrap_err(),
            fedimint_escrow_common::EscrowInputError::InvalidSeller
        ),
        "Expected InvalidSeller for forged signature"
    );
}

#[tokio::test]
async fn test_wrong_secret_code_rejected() {
    // Correct seller key + valid sig, but wrong secret code → InvalidSecretCode
    let escrow = test_escrow();
    let (db, _buyer_kp, seller_kp, _oracle_kps) = setup_escrow_for_input(
        &escrow,
        "wrong-secret",
        Amount::from_sats(5_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    let msg = [55u8; 32];
    let sig = sign(&seller_kp, &msg);

    let input = EscrowInput::ClamingWithoutDispute(EscrowInputClamingWithoutDispute {
        amount: Amount::from_sats(5_000),
        escrow_id: "wrong-secret".to_string(),
        secret_code: "WRONG_CODE".to_string(), // correct is "secret123"
        hashed_message: msg,
        signature: sig,
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Wrong secret code must be rejected");
    assert!(
        matches!(
            result.unwrap_err(),
            fedimint_escrow_common::EscrowInputError::InvalidSecretCode
        ),
        "Expected InvalidSecretCode"
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
        submitter_pubkey: random_service_kp().public_key(),
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

// ─── Delegated claim tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_claim_delegated_buyer_signs() {
    // ClaimDelegated: buyer signs SHA256(secret_code), service submits, e-cash goes to service
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, _oracle_kps) = setup_escrow_for_input(
        &escrow,
        "delegated-claim",
        Amount::from_sats(5_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    let secret = "secret123";
    let secret_hash = sha256_bytes(secret);
    let sig = sign(&buyer_kp, &secret_hash);

    // Service's key (different from buyer/seller)
    let secp = Secp256k1::new();
    let service_kp = Keypair::new(&secp, &mut OsRng);

    let input = EscrowInput::ClaimDelegated(EscrowInputClaimDelegated {
        amount: Amount::from_sats(5_000),
        escrow_id: "delegated-claim".to_string(),
        secret_code: secret.to_string(),
        hashed_message: secret_hash,
        external_signature: sig,
        submitter_pubkey: service_kp.public_key(),
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_ok(), "Delegated claim should succeed: {:?}", result.err());
    let meta = result.unwrap();
    // E-cash goes to SERVICE, not buyer
    assert_eq!(meta.pub_key, service_kp.public_key(), "E-cash must go to submitter (service)");
    assert_eq!(meta.amount.amounts, Amounts::new_bitcoin(Amount::from_sats(5_000)));
}

#[tokio::test]
async fn test_claim_delegated_wrong_signer_rejected() {
    // ClaimDelegated signed by seller (not buyer) → must fail
    let escrow = test_escrow();
    let (db, _buyer_kp, seller_kp, _oracle_kps) = setup_escrow_for_input(
        &escrow,
        "delegated-wrong-signer",
        Amount::from_sats(5_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    let secret = "secret123";
    let secret_hash = sha256_bytes(secret);
    let sig = sign(&seller_kp, &secret_hash); // WRONG: seller signs, but buyer_pubkey is checked

    let secp = Secp256k1::new();
    let service_kp = Keypair::new(&secp, &mut OsRng);

    let input = EscrowInput::ClaimDelegated(EscrowInputClaimDelegated {
        amount: Amount::from_sats(5_000),
        escrow_id: "delegated-wrong-signer".to_string(),
        secret_code: secret.to_string(),
        hashed_message: secret_hash,
        external_signature: sig,
        submitter_pubkey: service_kp.public_key(),
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Seller signing ClaimDelegated must fail");
    assert!(
        matches!(result.unwrap_err(), fedimint_escrow_common::EscrowInputError::InvalidBuyer),
        "Expected InvalidBuyer"
    );
}

#[tokio::test]
async fn test_claim_delegated_wrong_secret_rejected() {
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, _oracle_kps) = setup_escrow_for_input(
        &escrow,
        "delegated-wrong-secret",
        Amount::from_sats(5_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    let wrong_secret = "WRONG_CODE";
    let hash = sha256_bytes(wrong_secret);
    let sig = sign(&buyer_kp, &hash);

    let secp = Secp256k1::new();
    let service_kp = Keypair::new(&secp, &mut OsRng);

    let input = EscrowInput::ClaimDelegated(EscrowInputClaimDelegated {
        amount: Amount::from_sats(5_000),
        escrow_id: "delegated-wrong-secret".to_string(),
        secret_code: wrong_secret.to_string(),
        hashed_message: hash,
        external_signature: sig,
        submitter_pubkey: service_kp.public_key(),
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Wrong secret code must be rejected");
    assert!(
        matches!(result.unwrap_err(), fedimint_escrow_common::EscrowInputError::InvalidSecretCode),
        "Expected InvalidSecretCode"
    );
}

// ─── Delegated timeout claim tests ────────────────────────────────────────────

#[tokio::test]
async fn test_timeout_claim_delegated_refund_buyer_signs() {
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, _oracle_kps) = setup_escrow_for_input(
        &escrow,
        "delegated-timeout-refund",
        Amount::from_sats(10_000),
        1000,
        TimeoutAction::Refund,
    )
    .await;

    // SHA256("timeout") — the canonical message for timeout authorization
    let timeout_msg = sha256_bytes("timeout");
    let sig = sign(&buyer_kp, &timeout_msg);

    let secp = Secp256k1::new();
    let service_kp = Keypair::new(&secp, &mut OsRng);

    let input = EscrowInput::TimeoutClaimDelegated(EscrowInputTimeoutClaimDelegated {
        amount: Amount::from_sats(10_000),
        escrow_id: "delegated-timeout-refund".to_string(),
        hashed_message: timeout_msg,
        external_signature: sig,
        submitter_pubkey: service_kp.public_key(),
    });

    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&BlockHeightKey, &1500u64).await;

    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_ok(), "Delegated timeout (refund, buyer signs) should succeed: {:?}", result.err());
    let meta = result.unwrap();
    // E-cash to service, not buyer
    assert_eq!(meta.pub_key, service_kp.public_key(), "E-cash must go to submitter");
}

#[tokio::test]
async fn test_timeout_claim_delegated_release_seller_signs() {
    let escrow = test_escrow();
    let (db, _buyer_kp, seller_kp, _oracle_kps) = setup_escrow_for_input(
        &escrow,
        "delegated-timeout-release",
        Amount::from_sats(10_000),
        1000,
        TimeoutAction::Release,
    )
    .await;

    let timeout_msg = sha256_bytes("timeout");
    let sig = sign(&seller_kp, &timeout_msg);

    let secp = Secp256k1::new();
    let service_kp = Keypair::new(&secp, &mut OsRng);

    let input = EscrowInput::TimeoutClaimDelegated(EscrowInputTimeoutClaimDelegated {
        amount: Amount::from_sats(10_000),
        escrow_id: "delegated-timeout-release".to_string(),
        hashed_message: timeout_msg,
        external_signature: sig,
        submitter_pubkey: service_kp.public_key(),
    });

    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&BlockHeightKey, &1500u64).await;

    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_ok(), "Delegated timeout (release, seller signs) should succeed: {:?}", result.err());
    let meta = result.unwrap();
    assert_eq!(meta.pub_key, service_kp.public_key());
}

#[tokio::test]
async fn test_timeout_claim_delegated_wrong_signer_rejected() {
    // Refund timeout: buyer should sign, but seller signs → rejected
    let escrow = test_escrow();
    let (db, _buyer_kp, seller_kp, _oracle_kps) = setup_escrow_for_input(
        &escrow,
        "delegated-timeout-wrong-signer",
        Amount::from_sats(10_000),
        1000,
        TimeoutAction::Refund,
    )
    .await;

    let timeout_msg = sha256_bytes("timeout");
    let sig = sign(&seller_kp, &timeout_msg); // WRONG: seller signs for refund action

    let secp = Secp256k1::new();
    let service_kp = Keypair::new(&secp, &mut OsRng);

    let input = EscrowInput::TimeoutClaimDelegated(EscrowInputTimeoutClaimDelegated {
        amount: Amount::from_sats(10_000),
        escrow_id: "delegated-timeout-wrong-signer".to_string(),
        hashed_message: timeout_msg,
        external_signature: sig,
        submitter_pubkey: service_kp.public_key(),
    });

    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&BlockHeightKey, &1500u64).await;

    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Wrong signer for delegated timeout must fail");
    assert!(
        matches!(result.unwrap_err(), fedimint_escrow_common::EscrowInputError::InvalidBuyer),
        "Expected InvalidBuyer"
    );
}

// ─── Delegated dispute tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_dispute_delegated_buyer() {
    let escrow = test_escrow();
    let (db, buyer_kp, _seller_kp, _oracle_kps) = setup_escrow_for_input(
        &escrow,
        "delegated-dispute-buyer",
        Amount::from_sats(10_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    let dispute_msg = sha256_bytes("dispute");
    let sig = sign(&buyer_kp, &dispute_msg);

    let secp = Secp256k1::new();
    let service_kp = Keypair::new(&secp, &mut OsRng);

    let input = EscrowInput::DisputeDelegated(EscrowInputDisputeDelegated {
        escrow_id: "delegated-dispute-buyer".to_string(),
        disputer: buyer_kp.public_key(),
        hashed_message: dispute_msg,
        external_signature: sig,
        submitter_pubkey: service_kp.public_key(),
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_ok(), "Delegated dispute by buyer should succeed: {:?}", result.err());
    let meta = result.unwrap();
    assert_eq!(meta.pub_key, service_kp.public_key(), "E-cash token goes to submitter");
    // Dispute is zero-amount state change
    assert_eq!(meta.amount.amounts, Amounts::ZERO);

    // Verify state changed to DisputedByBuyer
    let mut dbtx2 = db.begin_transaction().await;
    let value: EscrowValue = dbtx2
        .get_value(&EscrowKey { escrow_id: "delegated-dispute-buyer".to_string() })
        .await
        .unwrap();
    assert_eq!(value.state, EscrowStates::DisputedByBuyer);
}

#[tokio::test]
async fn test_dispute_delegated_unauthorized_key_rejected() {
    // A third-party key (not buyer or seller) tries to dispute → rejected
    let escrow = test_escrow();
    let (db, _buyer_kp, _seller_kp, _oracle_kps) = setup_escrow_for_input(
        &escrow,
        "delegated-dispute-unauthorized",
        Amount::from_sats(10_000),
        9999,
        TimeoutAction::Refund,
    )
    .await;

    let secp = Secp256k1::new();
    let random_kp = Keypair::new(&secp, &mut OsRng);
    let service_kp = Keypair::new(&secp, &mut OsRng);

    let dispute_msg = sha256_bytes("dispute");
    let sig = sign(&random_kp, &dispute_msg);

    let input = EscrowInput::DisputeDelegated(EscrowInputDisputeDelegated {
        escrow_id: "delegated-dispute-unauthorized".to_string(),
        disputer: random_kp.public_key(),
        hashed_message: dispute_msg,
        external_signature: sig,
        submitter_pubkey: service_kp.public_key(),
    });

    let mut dbtx = db.begin_transaction().await;
    let result = escrow
        .process_input(&mut dbtx.to_ref_nc(), &input, dummy_in_point())
        .await;
    dbtx.commit_tx().await;

    assert!(result.is_err(), "Unauthorized key disputing must fail");
    assert!(
        matches!(result.unwrap_err(), fedimint_escrow_common::EscrowInputError::UnauthorizedToDispute),
        "Expected UnauthorizedToDispute"
    );
}
