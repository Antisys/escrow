# Fedimint Escrow — Upgrade Notes: v0.3.0 → v0.11.0-alpha

## Overview

This document records all breaking API changes encountered when upgrading
`fedimint-escrow` from v0.3.0 (Summer of Bitcoin 2024) to v0.11.0-alpha.

---

## New Crates

### `fedimint-client-module`
Split out from `fedimint-client`. Now contains all the types a module author
needs to implement a client module:

| Old path | New path |
|---|---|
| `fedimint_client::sm::*` | `fedimint_client_module::sm::*` |
| `fedimint_client::DynGlobalClientContext` | `fedimint_client_module::DynGlobalClientContext` |
| `fedimint_client::module::init::*` | `fedimint_client_module::module::init::*` |
| `fedimint_client::module::recovery::*` | `fedimint_client_module::module::recovery::*` |
| `fedimint_client::module::{ClientContext, ClientModule}` | `fedimint_client_module::module::{ClientContext, ClientModule}` |
| `fedimint_client::oplog::UpdateStreamOrOutcome` | `fedimint_client_module::oplog::UpdateStreamOrOutcome` |
| `fedimint_client::transaction::*` | `fedimint_client_module::transaction::*` |

### `fedimint-api-client`
New crate for federation API traits:

| Old path | New path |
|---|---|
| `fedimint_core::api::FederationApiExt` | `fedimint_api_client::api::FederationApiExt` |
| `fedimint_core::api::IModuleFederationApi` | `fedimint_api_client::api::IModuleFederationApi` |
| `fedimint_core::api::DynModuleApi` | `fedimint_api_client::api::DynModuleApi` |

`fedimint_core::module::ApiRequestErased` stays in `fedimint_core`.

---

## Server Module (`ServerModuleInit` trait)

### `DATABASE_VERSION` removed
Old:
```rust
const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);
```
New: remove entirely. Version tracking is now handled differently upstream.

### `#[async_trait]` removed (AFIT)
Old:
```rust
#[async_trait]
impl ModuleInit for EscrowInit { ... }
```
New: remove the `#[async_trait]` attribute. Fedimint now uses async functions in
traits (AFIT) natively.

### `input_amount` / `output_amount` → `input_fee` / `output_fee`
Old:
```rust
fn input_amount(&self, input: &EscrowInput) -> InputMeta { ... }
fn output_amount(&self, output: &EscrowOutput) -> OutputMeta { ... }
```
New:
```rust
fn input_fee(&self, amount: &Amounts, input: &EscrowInput) -> Option<Amount> { ... }
fn output_fee(&self, amount: &Amounts, output: &EscrowOutput) -> Option<Amount> { ... }
```
The `Amounts` parameter contains the ecash value being transacted. Return `None`
to signal an invalid input/output.

---

## Client Module

### `ClientInput` / `ClientOutput` split
State machines are now in separate structs:

Old:
```rust
ClientInput {
    input,
    keys: vec![self.key],
    amount,
    state_machines: Arc::new(move |txid, idx| vec![...]),
}
```
New:
```rust
let client_input = ClientInput {
    input,
    keys: vec![self.key],
    amounts: Amounts::new_bitcoin(amount),
};
let input_sm = ClientInputSM {
    state_machines: Arc::new(move |_: OutPointRange| vec![...]),
};
TransactionBuilder::new().with_inputs(
    self.client_ctx.make_client_inputs(
        ClientInputBundle::new(vec![client_input], vec![input_sm])
    )
)
```

### `StateGenerator` signature changed
Old: `|txid: TransactionId, idx: u64| -> Vec<...>`
New: `|range: OutPointRange| -> Vec<...>`

### `OutPointRange` moved
Old: `fedimint_client::module::OutPointRange` (was private)
New: `fedimint_core::OutPointRange`

### `finalize_and_submit_transaction` return type changed
Old: returns `(TransactionId, Vec<OutPoint>)`
New: returns `OutPointRange`

### `Context` trait requires `KIND`
Old:
```rust
impl Context for EscrowClientContext {}
```
New:
```rust
impl Context for EscrowClientContext {
    const KIND: Option<ModuleKind> = None;
}
```

---

## `fedimintd` binary

### `Fedimintd` builder pattern removed
Old:
```rust
Fedimintd::new(fedimint_build_code_version_env!())?
    .with_default_modules()
    .with_module_kind(EscrowInit)
    .with_module_instance(KIND, EscrowGenParams::default())
    .run()
    .await
```
New:
```rust
let mut modules = fedimintd::default_modules();
modules.attach(EscrowInit);
fedimintd::run(modules, fedimint_build_code_version_env!(), None).await?;
unreachable!()
```
Genesis params (previously `with_module_instance`) are now configured during
federation setup, not at binary startup.

---

## Dependency Changes (`Cargo.toml`)

```toml
# Added
fedimint-client-module = { path = "../fedimint/fedimint-client-module" }
fedimint-api-client = { path = "../fedimint/fedimint-api-client" }

# clap needs derive feature for #[derive(Parser)]
clap = { version = "4.5.8", features = ["derive"] }
```

---

## secp256k1 / Keypair

`KeyPair` was renamed to `Keypair` (lowercase p) in secp256k1 0.29.

---

## Build Notes

### Always build the custom fedimintd with `-p fedimintd-custom`

```bash
cargo build -p fedimintd-custom
```

**Do NOT use `-p fedimintd`** — that builds the upstream Fedimint daemon (without the
escrow module) and overwrites `target/debug/fedimintd` with a binary that returns
`"No module with this kind found"` for all escrow commands. This is a silent failure
that is hard to diagnose.

The workspace has two packages that produce a `fedimintd` binary:
- `fedimintd-custom` (path: `fedimintd/`) — our custom daemon with `EscrowInit` attached ✅
- `fedimintd` (workspace dep: `../fedimint/fedimintd`) — upstream, no escrow ❌

### Running E2E tests

```bash
# All three tests in one devimint session:
bash scripts/dev/run-all-e2e.sh

# Individual tests (require devimint already running):
bash scripts/dev/e2e-happy-path.sh
bash scripts/dev/e2e-timeout-path.sh
bash scripts/dev/e2e-dispute-flow.sh
```

### Fedimint mint fees

Fedimint charges ecash mint fees on both the lock and unlock side. At devimint
defaults, expect approximately:
- Happy path: buyer −10624 msat, seller +7422 msat (on 10000 msat escrow)
- Dispute (oracle): buyer −10496 msat, seller +9472 msat
- Timeout refund: buyer delta −1760 msat (most of the escrow returned)

This is expected behavior — not a bug.

---

## Known Issues

- `fedimint-ldk-node` in the upstream checkout has an `electrum_client` version
  conflict that prevents `cargo test --workspace`. The escrow crates themselves
  test cleanly with `cargo test -p fedimint-escrow-{common,server,client}`.

- The nix dev shell is pinned to Rust 1.77.2 which predates `edition2024`
  support (requires Cargo ≥ 1.85). Use the system cargo outside the nix shell.
