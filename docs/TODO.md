# Fedimint Escrow — Master Todo List

Last updated: 2026-02-23 (Phase 3 complete, Phase 4 Rust + Python bridge complete)
Legend: [ ] pending  [x] done  [~] in progress  [!] blocked

---

## Phase 0: Dev Environment

- [x] Verify Nix installation (`nix --version`)
- [x] Enter Fedimint dev shell (`nix develop` completes)
- [x] Verify Rust toolchain inside dev shell (`rustc --version`)
- [ ] Verify devimint available (`devimint --help`)
- [ ] Full `cargo build` succeeds on Fedimint repo (CARGO_TARGET_DIR=/tmp/fedimint-target)
- [x] Fix /home disk space (deleted Android folder, 8GB free now)
- [ ] Clone custom modules example for reference
- [ ] Trusted user added to Nix substituter config (warning still showing)

---

## Phase 1: Upgrade Existing Module (was: Build Skeleton)

**Context:** Existing module found at https://github.com/harsh-ps-2003/escrow (Harsh Pratap Singh, Summer of Bitcoin 2024). Already cloned at /home/ralf/fedimint-escrow/. Targets v0.3.0, needs upgrade to v0.11.0-alpha.

**Known issues to fix during upgrade:**
- Bug: WaitingforBuyerToClaim uses seller_pubkey instead of buyer_pubkey
- audit() is commented out — uncomment and fix
- fs-lock crate fails cargo check (transitive dep, fixed by updating Fedimint version)

### Upgrade tasks
- [x] Read v0.11 API changes (compare dummy module v0.3 vs v0.11)
- [x] Update Cargo.toml to fedimint v0.11.0-alpha (path deps to local checkout)
- [x] Run `cargo check` with CARGO_TARGET_DIR=/tmp/escrow-target
- [x] Fix Category A errors: changed trait method signatures
- [x] Fix Category B errors: renamed/restructured types (InputMeta, TransactionItemAmounts)
- [x] Fix Category C errors: removed upstream crates (fs-lock)
- [x] Fix Bug: WaitingforBuyerToClaim → use buyer_pubkey not seller_pubkey
- [x] Enable audit(): uncomment, fix compilation
- [x] `cargo check` passes with zero errors (full workspace, all 5 crates)
- [x] `cargo build` succeeds
- [x] `cargo test` passes (no existing unit tests; escrow crates exit 0)
- [x] Write UPGRADE_NOTES.md (what changed between v0.3 and v0.11)

---

## Phase 2: Server Additions

**Context:** Existing module already has: state machine, Schnorr sig verification, secret code, single arbiter dispute. Missing: timelock escape, LN payout trigger, verified audit.

- [x] Add `timeout_block: u32` to EscrowOutput
- [x] Add `timeout_action: TimeoutAction` to EscrowOutput
- [x] Add `TimeoutAction` enum (Release / Refund) to common crate
- [x] Add `EscrowInput::TimeoutClaim` variant
- [x] Add `EscrowInputTimeoutClaim` struct
- [x] Implement timeout arm in `process_input` (block height check + sig verify)
- [x] Verify audit() reports correct liabilities
- [x] Write test: timeout claim before timeout block (expect error)
- [x] Write test: timeout claim after timeout block, correct key (expect success)
- [x] Write test: timeout claim after timeout block, wrong key (expect error)
- [x] Write test: audit balance (create N, release M, verify sum)
- [x] Document LN payout trigger: service layer calls lnd after Fedimint confirms
- [x] All tests pass: `cargo test`

---

## Phase 3: Nostr Oracle

**Context:** Replace single `arbiter_pubkey: PublicKey` with `oracle_pubkeys: [PublicKey; 3]` and 2-of-3 threshold verification.

- [x] Create `oracle.rs` in common crate
- [x] Define `OracleAttestationContent` struct (escrow_id, outcome, decided_at, reason)
- [x] Define `SignedAttestation` struct (pubkey, signature, content)
- [x] Define `ORACLE_ATTESTATION_KIND` constant (30001)
- [x] Replace `arbiter_pubkey: PublicKey` with `oracle_pubkeys: Vec<PublicKey>` in EscrowOutput
- [x] Implement `verify_attestation()` (single Schnorr signature check)
- [x] Implement `verify_threshold()` (2-of-3 agreeing signatures, pubkey dedup, conflict detection)
- [x] Replace single-arbiter `ArbiterDecision` input path with `OracleAttestation` path
- [x] Implement `consensus_proposal()` (propagate pending attestations)
- [x] Implement `process_consensus_item()` (validate + store attestations in PendingOracleAttestation DB)
- [x] Create `tools/oracle_sign.py` for testing
- [x] Write test: single valid signature (threshold fails — needs 2)
- [x] Write test: two valid signatures same outcome (threshold passes — buyer wins + seller wins)
- [x] Write test: conflicting outcomes rejected
- [x] Write test: unknown oracle pubkey rejected
- [x] Write test: wrong escrow_id rejected
- [x] Write test: duplicate oracle pubkey counts once
- [x] Write test: non-disputed state rejected
- [x] All oracle tests pass (17 total, 0 failed)

---

## Phase 4: Client Module

- [x] Understand existing client module (`/home/ralf/fedimint-escrow/fedimint-escrow-client/`)
- [x] Implement `create_escrow()` (submit EscrowOutput transaction)
- [x] Implement `claim_escrow()` / cooperative release (submit ClamingWithoutDispute input)
- [x] Implement `initiate_dispute()` (submit Disputing input)
- [x] Implement `resolve_via_oracle()` (submit OracleAttestation input)
- [x] Implement `claim_timeout()` (submit TimeoutClaim input after timeout)
- [x] CLI commands: create, info, claim, dispute, resolve-oracle, claim-timeout, public-key
- [x] Create Python bridge `backend/fedimint/escrow_client.py`
- [x] Test `create_escrow` via Python bridge (mocked subprocess, 13 tests passing)
- [x] Test `claim_escrow` / `initiate_dispute` / `resolve_via_oracle` / `claim_timeout` via Python bridge
- [x] Error hierarchy: EscrowClientError → EscrowNotFoundError, EscrowStateError
- [ ] `cargo test` passes (all client tests — needs devimint integration test)

---

## Phase 5: Integration

- [ ] Create `backend/fedimint/` directory
- [ ] Create `backend/fedimint/escrow_client.py`
- [ ] Create `backend/fedimint/oracle_listener.py`
- [ ] Replace vault calls in `deals.py` with Fedimint client calls
- [ ] Replace `liquidSigner.js` with simple message signing
- [ ] Update `crypto.js` — remove ephemeral key/Liquid logic
- [ ] Add `fedimint_escrow_id` column to deals table
- [ ] Run database migration
- [ ] Configure NOSTR_RELAYS in oracle listener
- [ ] Configure ORACLE_PUBKEYS in oracle listener
- [ ] Full deal flow E2E on devimint (fund → release → payout)
- [ ] Dispute flow E2E on devimint (dispute → oracle → payout)
- [ ] Remove Liquid dependencies (after new flow confirmed working)

---

## Phase 6: Testing

- [ ] Happy path: fund → release → payout
- [ ] Happy path: fund → refund → payout
- [ ] Dispute path: 1 oracle sig (nothing) → 2nd sig → resolution
- [ ] Timeout path: expire block → claim → payout
- [ ] Security: double-spend rejected
- [ ] Security: wrong signature rejected
- [ ] Security: unknown oracle pubkey rejected
- [ ] Security: conflicting oracle outcomes rejected
- [ ] Security: early timeout rejected
- [ ] Security: zero amount rejected
- [ ] Security: duplicate escrow_id rejected
- [ ] Audit: sum of liabilities = 0 after every operation
- [ ] devimint E2E test runs fully automated

---

## Phase 7: Federation

- [ ] Decide on 4 VPS providers and locations
- [ ] Provision 4 VPS instances
- [ ] Deploy Fedimint guardian software
- [ ] Complete federation setup ceremony (DKG)
- [ ] Deploy escrow module to federation
- [ ] Configure 3 oracle arbitrator pubkeys
- [ ] Update service to point to real federation
- [ ] Recruit guardian 2 (independent operator)
- [ ] Recruit guardian 3 (independent operator)
- [ ] Recruit guardian 4 (independent operator)
- [ ] Recruit oracle arbitrator 2
- [ ] Recruit oracle arbitrator 3
- [ ] Set up guardian monitoring
- [ ] Apply for OpenSats grant
- [ ] Apply for HRF grant
- [ ] Publish project on Nostr

---

## Ongoing / Future

- [ ] Write arbitrator handbook (how to review evidence, how to sign)
- [ ] Write guardian handbook (how to run a node, responsibilities)
- [ ] Security audit of escrow module
- [ ] Formal legal review of operator position
- [ ] BOLT12 offers support (removes need for pre-created invoices)
- [ ] Mobile-friendly arbitrator signing tool
- [ ] Public evidence submission UI for disputed deals
- [ ] Multi-language frontend (German, Spanish, Portuguese)

---

*Total tasks: ~110  |  Completed: 52  |  Phase 4 complete — next: Phase 5 Integration (oracle_listener.py, replace vault calls in deals.py)*
