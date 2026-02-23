# Phase 1: Upgrade Existing Module to v0.11

**Goal:** Fork Harsh Pratap Singh's fedimint-escrow module, upgrade it from Fedimint v0.3.0 to v0.11.0-alpha, and fix the known issues — so `cargo check` passes and all tests run.
**Prerequisite:** Phase 0 complete (nix develop works, Fedimint compiles)
**Estimated effort:** 1–2 weeks (upgrade is harder than building fresh skeleton)
**Starting point:** `/home/ralf/fedimint-escrow/` (already cloned)

---

## Context for Claude

We are NOT building from scratch. The existing module at https://github.com/harsh-ps-2003/escrow already has the correct three-crate structure, state machine, signature verification, secret code mechanism, and tests. Our job is to:

1. Update `Cargo.toml` to point at Fedimint v0.11.0-alpha
2. Fix compilation errors from the API changes between v0.3.0 and v0.11.0
3. Fix the known bug and enable audit
4. Verify all tests pass under the new version

The Nostr oracle replacement (Phase 3) and Lightning payout (Phase 2) are NOT part of this phase. The goal here is a compiling, tested, correct v0.11 port of the existing module — with the known bugs fixed.

---

## Existing Codebase Structure

```
/home/ralf/fedimint-escrow/
+-- Cargo.toml                      <- workspace root, targets v0.3.0 (needs update)
+-- fedimint-escrow-common/
|   +-- src/lib.rs                  <- shared types (EscrowStates, inputs, outputs)
+-- fedimint-escrow-server/
|   +-- src/lib.rs                  <- guardian logic (process_input, process_output)
|   +-- src/db.rs                   <- database keys
+-- fedimint-escrow-client/
|   +-- src/lib.rs                  <- client module
+-- tests/
    +-- ...                         <- integration tests (devimint)
```

---

## Known Issues in the Existing Code

### Bug 1: Wrong pubkey returned for buyer claim

In `fedimint-escrow-server/src/lib.rs`, the `WaitingforBuyerToClaim` match arm returns `seller_pubkey` instead of `buyer_pubkey`:

```rust
// WRONG (existing code):
EscrowStates::WaitingforBuyerToClaim => {
    // ...
    let pubkey = escrow.seller_pubkey;  // BUG: should be buyer_pubkey
}

// CORRECT:
EscrowStates::WaitingforBuyerToClaim => {
    // ...
    let pubkey = escrow.buyer_pubkey;
}
```

Fix this immediately — it could allow the wrong party to claim funds.

### Bug 2: audit() commented out

The `audit()` method is commented out in the server. This means the federation cannot verify that its ecash liabilities match locked escrow funds. Uncomment and implement it.

### Structural limitation: single arbiter

The existing module has `arbiter_pubkey: PublicKey` (single key). We will replace this with `oracle_pubkeys: [PublicKey; 3]` in Phase 3. For this phase, leave the single arbiter in place and just get the code compiling.

---

## Tasks

### Task 1.1 — Understand the version gap

Read the Fedimint changelog or migration notes between v0.3.0 and v0.11.0-alpha.

Key areas that changed between v0.3 and v0.11:
- `ServerModule` trait signatures (async fn, lifetime parameters)
- `process_input` / `process_output` return types
- Database transaction API (`DatabaseTransaction` wrapper changes)
- `InputMeta` structure
- `TransactionItemAmounts` fields
- `CommonModuleInit` requirements
- `ModuleConsensusVersion` format

Start by reading the current Fedimint module examples:

```bash
# Inside nix develop in /home/ralf/fedimint/
grep -r "impl ServerModule" modules/ --include="*.rs" -l
# Read the simplest one: fedimint-dummy-server/src/lib.rs
```

---

### Task 1.2 — Update Cargo.toml dependencies

In `/home/ralf/fedimint-escrow/Cargo.toml`, change:

```toml
# Old (v0.3.0):
fedimint-core = { git = "https://github.com/fedimint/fedimint", tag = "v0.3.0" }
fedimint-server = { git = "https://github.com/fedimint/fedimint", tag = "v0.3.0" }
fedimint-client = { git = "https://github.com/fedimint/fedimint", tag = "v0.3.0" }
# ... etc

# New (v0.11.0-alpha — use the exact same version as the main repo):
fedimint-core = { git = "https://github.com/fedimint/fedimint", branch = "main" }
fedimint-server = { git = "https://github.com/fedimint/fedimint", branch = "main" }
fedimint-client = { git = "https://github.com/fedimint/fedimint", branch = "main" }
# ... etc
```

Note: Use `branch = "main"` initially to get the latest. Once stable, pin to a specific commit hash.

Set CARGO_TARGET_DIR to avoid filling /home:

```bash
export CARGO_TARGET_DIR=/tmp/escrow-target
cargo check 2>&1 | tee /tmp/escrow-check.log
```

---

### Task 1.3 — Fix compilation errors

Run `cargo check` and fix each error systematically. Expect errors in three categories:

**Category A: Changed function signatures**

The `ServerModule` trait evolves. Match the new signatures from the dummy module:

```bash
# Reference: current dummy module in the Fedimint repo
cat /home/ralf/fedimint/modules/fedimint-dummy-server/src/lib.rs
```

**Category B: Changed types**

`InputMeta`, `TransactionItemAmounts`, `OutPoint` etc. may have changed fields. Use the compiler errors as a guide, and cross-reference with current Fedimint source.

**Category C: Removed/renamed crates**

The `fs-lock` crate fails (2 errors in v0.3.0 build). This is a transitive dependency, not our code. Updating the Fedimint version to v0.11 should resolve this.

---

### Task 1.4 — Fix Bug 1 (wrong pubkey)

In `fedimint-escrow-server/src/lib.rs`, find the `WaitingforBuyerToClaim` arm and fix the pubkey:

```rust
// Find this pattern and fix:
EscrowStates::WaitingforBuyerToClaim => {
    if pubkey != escrow.buyer_pubkey {  // was: seller_pubkey
        return Err(EscrowInputError::InvalidBuyer);
    }
}
```

Verify the fix with a test that exercises this code path.

---

### Task 1.5 — Enable audit()

Find the commented-out `audit()` implementation in `fedimint-escrow-server/src/lib.rs`. Uncomment it and fix any compilation issues from the v0.3→v0.11 API changes.

The audit function must return a negative liability for every locked escrow:

```rust
async fn audit(
    &self,
    dbtx: &mut DatabaseTransaction<'_>,
    audit: &mut Audit,
    module_instance_id: ModuleInstanceId,
) {
    // Report negative liability for each locked escrow
    // Sum of all audit items must equal zero after all escrows are resolved
}
```

---

### Task 1.6 — Run existing tests

```bash
cd /home/ralf/fedimint-escrow
export CARGO_TARGET_DIR=/tmp/escrow-target
cargo test 2>&1 | tee /tmp/escrow-test.log
```

Fix any test failures. The existing tests cover:
- Create escrow
- Seller claims without dispute (secret code)
- Dispute initiation
- Arbiter decision
- Claim after dispute

---

### Task 1.7 — Document the API changes found

After completing the upgrade, write a short `UPGRADE_NOTES.md` in the fedimint-escrow directory listing:
- Which trait methods changed signature
- Which types were renamed/restructured
- Any gotchas for future reference

This will be invaluable if we ever need to upgrade Fedimint again.

---

## What We Are NOT Doing in This Phase

- No Nostr oracle (Phase 3) — leave single `arbiter_pubkey` for now
- No Lightning payout (Phase 2) — ecash goes directly to winner, same as original
- No timelock escape path (Phase 2)
- No changes to the state machine — only compatibility fixes

The goal is: **port the existing working module to v0.11 with bugs fixed**.

---

## Definition of Done

- [ ] `Cargo.toml` targets Fedimint v0.11.0-alpha
- [ ] `cargo check` passes with zero errors
- [ ] `cargo build` succeeds
- [ ] Bug 1 fixed: `WaitingforBuyerToClaim` uses `buyer_pubkey`
- [ ] `audit()` is enabled (uncommented and compiling)
- [ ] `cargo test` passes (all existing tests)
- [ ] `UPGRADE_NOTES.md` written

---

## Key References

- Existing module: `/home/ralf/fedimint-escrow/` (already cloned)
- Dummy module (reference for v0.11 API): `/home/ralf/fedimint/modules/fedimint-dummy-server/`
- Common module reference: `/home/ralf/fedimint/modules/fedimint-dummy-common/`
- Mint module (simplest with audit): `/home/ralf/fedimint/modules/fedimint-mint-server/`

---

*Next: See 03_PHASE_2_SERVER.md*
