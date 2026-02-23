# Phase 4: Client Module

**Goal:** Users can create deals, fund escrow via Lightning, and receive Lightning payouts.
**Prerequisite:** Phase 2 complete (server logic works). Phase 3 can run in parallel.
**Estimated effort:** 1–2 weeks

---

## Context for Claude

The client module runs on the user's device (or on the service backend acting on behalf of users). It builds Fedimint transactions and submits them to the federation.

The client module does NOT replace the existing FastAPI backend. The existing backend handles:
- Deal metadata (title, description, status)
- User sessions and LNURL-auth
- Frontend API

The Fedimint client module handles:
- Actual fund locking (replaces Liquid multisig)
- Actual fund release/refund (replaces pre-signed TX broadcast)
- Lightning payout (via Fedimint's built-in Lightning module)

The backend calls the Fedimint client module via a Rust library embedded in the service, OR via the Fedimint HTTP API if running as a separate process.

---

## Tasks

### Task 4.1 — Define client module structure

In `fedimint-escrow-client/src/lib.rs`:

```rust
#[derive(Debug, Clone)]
pub struct EscrowClientModule {
    pub cfg: EscrowClientConfig,
    pub key_pair: secp256k1::KeyPair,  // this client's key (buyer or seller)
    pub client_ctx: ClientContext<Self>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowClientConfig {
    pub federation_id: FederationId,
    pub oracle_pubkeys: [nostr::PublicKey; 3],
    pub fee_per_escrow: Amount,
}
```

---

### Task 4.2 — Implement create_escrow

Called by the service when a deal is funded (buyer pays Lightning invoice).

```rust
impl EscrowClientModule {
    pub async fn create_escrow(
        &self,
        params: CreateEscrowParams,
    ) -> Result<EscrowId, EscrowClientError> {

        let escrow_id = EscrowId::random();

        // Build the EscrowOutput
        let output = EscrowOutput {
            contract: EscrowContract {
                escrow_id,
                buyer_key: params.buyer_pubkey,
                seller_key: params.seller_pubkey,
                amount: params.amount,
                conditions_hash: params.conditions_hash,
                timeout_block: params.timeout_block,
                timeout_action: params.timeout_action,
                status: EscrowStatus::Funded,
                oracle_pubkeys: self.cfg.oracle_pubkeys.map(|k| k.into()),
            },
        };

        // Submit transaction to federation
        // The ecash to fund this comes from the federation's Lightning module
        // (buyer already paid the LN invoice to get ecash into the federation)
        let tx = self.client_ctx
            .transaction_builder()
            .with_output(self.client_ctx.make_client_output(output))
            .build_and_submit(&mut self.client_ctx.get_or_open_db().await?)
            .await?;

        // Wait for transaction to be confirmed by federation
        self.client_ctx.await_primary_module_output(tx, 0).await?;

        Ok(escrow_id)
    }
}
```

---

### Task 4.3 — Implement release (cooperative)

Called when buyer clicks "Release" and both parties sign.

```rust
pub async fn release_cooperative(
    &self,
    escrow_id: EscrowId,
    buyer_sig: secp256k1::ecdsa::Signature,
    seller_sig: secp256k1::ecdsa::Signature,
    payout_invoice: String,
) -> Result<(), EscrowClientError> {

    let input = EscrowInput::Cooperative {
        escrow_id,
        buyer_sig,
        seller_sig,
        beneficiary: Beneficiary::Seller,
    };

    // Build transaction: escrow input → LN outgoing contract output
    // The LN outgoing contract pays the seller's invoice
    let ln_output = self.build_ln_payout_output(&payout_invoice).await?;

    let tx = self.client_ctx
        .transaction_builder()
        .with_input(self.client_ctx.make_client_input(input))
        .with_output(ln_output)
        .build_and_submit(...)
        .await?;

    self.client_ctx.await_primary_module_output(tx, 0).await?;

    Ok(())
}
```

---

### Task 4.4 — Implement refund (cooperative)

Mirror of release but beneficiary = Buyer.

```rust
pub async fn refund_cooperative(
    &self,
    escrow_id: EscrowId,
    buyer_sig: secp256k1::ecdsa::Signature,
    seller_sig: secp256k1::ecdsa::Signature,
    refund_invoice: String,
) -> Result<(), EscrowClientError> {
    // Same as release but Beneficiary::Buyer and refund_invoice
    todo!()
}
```

---

### Task 4.5 — Implement oracle-based release/refund

Called when oracle attestations are received (2-of-3 arbitrators signed).

```rust
pub async fn resolve_via_oracle(
    &self,
    escrow_id: EscrowId,
    attestations: Vec<SignedAttestation>,
    payout_invoice: String,
) -> Result<(), EscrowClientError> {

    let input = EscrowInput::OracleAttestation {
        escrow_id,
        attestations,
    };

    // Build LN payout to winner
    let ln_output = self.build_ln_payout_output(&payout_invoice).await?;

    let tx = self.client_ctx
        .transaction_builder()
        .with_input(self.client_ctx.make_client_input(input))
        .with_output(ln_output)
        .build_and_submit(...)
        .await?;

    Ok(())
}
```

---

### Task 4.6 — Implement timeout claim

Called after timeout block expires (service is gone, beneficiary self-recovers).

```rust
pub async fn claim_timeout(
    &self,
    escrow_id: EscrowId,
    beneficiary_key: secp256k1::KeyPair,
    payout_invoice: String,
) -> Result<(), EscrowClientError> {

    let msg = timeout_claim_message(&escrow_id);
    let sig = beneficiary_key.sign_ecdsa(msg);

    let input = EscrowInput::Timeout {
        escrow_id,
        beneficiary_sig: sig,
    };

    let ln_output = self.build_ln_payout_output(&payout_invoice).await?;

    let tx = self.client_ctx
        .transaction_builder()
        .with_input(self.client_ctx.make_client_input(input))
        .with_output(ln_output)
        .build_and_submit(...)
        .await?;

    Ok(())
}
```

---

### Task 4.7 — Build LN payout helper

This connects to Fedimint's built-in Lightning module to pay the winner's invoice.

```rust
async fn build_ln_payout_output(
    &self,
    bolt11_invoice: &str,
) -> Result<ClientOutput<LightningOutput>, EscrowClientError> {
    // Use Fedimint's lightning client module
    // This creates an outgoing LN contract
    // The federation pays the invoice and claims the escrow funds
    let ln_client = self.client_ctx.get_module_client::<LightningClientModule>()?;
    let (output, _) = ln_client.create_outgoing_ln_contract(bolt11_invoice).await?;
    Ok(output)
}
```

---

### Task 4.8 — Python/FastAPI bridge

The existing FastAPI backend needs to call the Rust client module.

Options (in order of simplicity):
1. **Fedimint HTTP client**: Run the Fedimint client as a separate process with HTTP API (`fedimint-cli`). FastAPI calls it via HTTP. No Rust required in the Python service.
2. **PyO3 bindings**: Wrap the Rust client module in Python bindings. More complex but tighter integration.
3. **Separate Rust service**: Write a small Rust HTTP service wrapping the client module. FastAPI calls it.

**Recommended for Phase 4: Option 1 (fedimint-cli)**

The existing `fedimint-cli` tool can be called from Python as a subprocess:
```python
import subprocess, json

def create_escrow(params: dict) -> str:
    result = subprocess.run(
        ["fedimint-cli", "module", "escrow", "create", json.dumps(params)],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)["escrow_id"]
```

This is not production-grade but works for early testing.

---

## Definition of Done

- [ ] `create_escrow()` builds and submits EscrowOutput transaction
- [ ] `release_cooperative()` builds and submits cooperative release transaction
- [ ] `refund_cooperative()` builds and submits cooperative refund transaction
- [ ] `resolve_via_oracle()` builds and submits oracle attestation transaction
- [ ] `claim_timeout()` builds and submits timeout claim
- [ ] LN payout helper connects to Fedimint Lightning module
- [ ] Python bridge (subprocess or HTTP) allows FastAPI to call the client
- [ ] `cargo test` passes

---

*Next: See 06_PHASE_5_INTEGRATION.md*
