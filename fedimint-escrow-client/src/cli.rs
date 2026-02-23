use std::{ffi, iter};

use clap::Parser;
use fedimint_core::Amount;
use fedimint_escrow_common::endpoints::EscrowInfo;
use fedimint_escrow_common::oracle::{Beneficiary, OracleAttestationContent, SignedAttestation};
use fedimint_escrow_common::{TimeoutAction, hash256};
use random_string::generate;
use secp256k1::PublicKey;
use secp256k1::schnorr::Signature;
use serde::Serialize;
use serde_json::json;

use super::EscrowClientModule;
use crate::api::EscrowFederationApi;

#[derive(Parser, Serialize)]
enum Command {
    Create {
        seller_pubkey: PublicKey,
        /// First registered oracle pubkey (Nostr arbitrator 1)
        oracle_pubkey1: PublicKey,
        /// Second registered oracle pubkey (Nostr arbitrator 2)
        oracle_pubkey2: PublicKey,
        /// Third registered oracle pubkey (Nostr arbitrator 3)
        oracle_pubkey3: PublicKey,
        cost: Amount,
        /// Bitcoin block height after which the timeout escape is available
        timeout_block: u32,
        /// Who gets funds on timeout: "release" (seller) or "refund" (buyer)
        #[arg(default_value = "refund")]
        timeout_action: String,
    },
    Info {
        escrow_id: String,
    },
    Claim {
        escrow_id: String,
        secret_code: String,
    },
    Dispute {
        escrow_id: String,
    },
    /// Resolve a disputed escrow via 2-of-3 oracle attestations.
    /// Pass attestations as a JSON array of SignedAttestation objects.
    ResolveOracle {
        escrow_id: String,
        /// JSON array of SignedAttestation objects (from oracle_sign.py)
        attestations_json: String,
    },
    /// Claim an escrow after the timelock has expired.
    ClaimTimeout {
        escrow_id: String,
    },
    PublicKey {},
}

/// Handles the CLI command for the escrow module
pub(crate) async fn handle_cli_command(
    escrow: &EscrowClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let command =
        Command::parse_from(iter::once(ffi::OsString::from("escrow")).chain(args.iter().cloned()));

    let res = match command {
        Command::Create {
            seller_pubkey,
            oracle_pubkey1,
            oracle_pubkey2,
            oracle_pubkey3,
            cost,
            timeout_block,
            timeout_action,
        } => {
            let escrow_id: String = generate(
                32,
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            );
            let secret_code: String = generate(
                32,
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            );
            let secret_code_hash = hash256(secret_code.clone());

            let timeout_action_parsed = match timeout_action.to_lowercase().as_str() {
                "release" => TimeoutAction::Release,
                _ => TimeoutAction::Refund,
            };

            escrow
                .create_escrow(
                    cost,
                    seller_pubkey,
                    vec![oracle_pubkey1, oracle_pubkey2, oracle_pubkey3],
                    escrow_id.clone(),
                    secret_code_hash,
                    timeout_block,
                    timeout_action_parsed,
                )
                .await?;

            Ok(json!({
                "secret-code": secret_code,
                "escrow-id": escrow_id,
                "state": "escrow opened!"
            }))
        }
        Command::Info { escrow_id } => {
            let escrow_value: EscrowInfo =
                escrow.module_api.get_escrow_info(escrow_id.clone()).await?;

            Ok(json!({
                "buyer_pubkey": escrow_value.buyer_pubkey,
                "seller_pubkey": escrow_value.seller_pubkey,
                "oracle_pubkeys": [
                    escrow_value.oracle_pubkeys[0],
                    escrow_value.oracle_pubkeys[1],
                    escrow_value.oracle_pubkeys[2],
                ],
                "amount": escrow_value.amount,
                "state": escrow_value.state,
                "timeout_block": escrow_value.timeout_block,
                "timeout_action": escrow_value.timeout_action,
            }))
        }
        Command::Claim {
            escrow_id,
            secret_code,
        } => {
            let escrow_value: EscrowInfo =
                escrow.module_api.get_escrow_info(escrow_id.clone()).await?;

            escrow
                .claim_escrow(escrow_id.clone(), escrow_value.amount, secret_code)
                .await?;

            Ok(json!({
                "escrow_id": escrow_id,
                "status": "resolved"
            }))
        }
        Command::Dispute { escrow_id } => {
            escrow.initiate_dispute(escrow_id.clone()).await?;

            Ok(json!({
                "escrow_id": escrow_id,
                "status": "disputed!"
            }))
        }
        Command::ResolveOracle {
            escrow_id,
            attestations_json,
        } => {
            // Parse attestations from JSON. Each element is:
            // { "pubkey": "<hex>", "signature": "<hex>", "content": { "escrow_id": "...",
            //   "outcome": "buyer"|"seller", "decided_at": <u64>, "reason": "..." } }
            let raw: Vec<serde_json::Value> = serde_json::from_str(&attestations_json)
                .map_err(|e| anyhow::anyhow!("Invalid attestations JSON: {e}"))?;

            let mut attestations: Vec<SignedAttestation> = Vec::with_capacity(raw.len());
            for entry in &raw {
                let pubkey_hex = entry["pubkey"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing pubkey"))?;
                let sig_hex = entry["signature"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing signature"))?;
                let content = &entry["content"];

                let pubkey = pubkey_hex
                    .parse::<PublicKey>()
                    .map_err(|e| anyhow::anyhow!("bad pubkey: {e}"))?;
                let sig_bytes = hex::decode(sig_hex)
                    .map_err(|e| anyhow::anyhow!("bad signature hex: {e}"))?;
                let signature = Signature::from_slice(&sig_bytes)
                    .map_err(|e| anyhow::anyhow!("bad schnorr signature: {e}"))?;

                let outcome_str = content["outcome"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing outcome"))?;
                let outcome = match outcome_str {
                    "buyer" => Beneficiary::Buyer,
                    "seller" => Beneficiary::Seller,
                    other => return Err(anyhow::anyhow!("unknown outcome: {other}")),
                };
                let att_escrow_id = content["escrow_id"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing content.escrow_id"))?
                    .to_string();
                let decided_at = content["decided_at"]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("missing decided_at"))?;
                let reason = content["reason"].as_str().map(|s| s.to_string());

                attestations.push(SignedAttestation {
                    pubkey,
                    signature,
                    content: OracleAttestationContent {
                        escrow_id: att_escrow_id,
                        outcome,
                        decided_at,
                        reason,
                    },
                });
            }

            escrow
                .resolve_via_oracle(escrow_id.clone(), attestations)
                .await?;

            Ok(json!({
                "escrow_id": escrow_id,
                "status": "resolved via oracle"
            }))
        }
        Command::ClaimTimeout { escrow_id } => {
            escrow.claim_timeout(escrow_id.clone()).await?;

            Ok(json!({
                "escrow_id": escrow_id,
                "status": "timeout claimed"
            }))
        }
        Command::PublicKey {} => Ok(json!({
            "public_key": escrow.key.public_key().to_string()
        })),
    };

    res
}
