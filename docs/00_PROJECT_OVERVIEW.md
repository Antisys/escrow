# Fedimint Escrow — Project Overview

**Version:** 1.0
**Date:** February 2026
**Author:** Ralf Dittmer

---

## 1. The Problem

Peer-to-peer trade between strangers requires trust. When buyer and seller don't know each other, one party must move first — and risks losing their money. Existing solutions all have a fatal flaw:

- **Centralised escrow services** (PayPal, Escrow.com): custodial, freeze-able, KYC-required, single point of legal attack
- **Multisig with human arbitrator** (Bisq, AGORA): the arbitrator's key = the attack surface
- **Smart contracts** (Ethereum-based): requires users to hold a separate token, high fees, complex UX
- **Existing Lightning escrow attempts**: service holds pre-signed transactions, which regulators can argue is custody

The deeper problem: **any service that can be compelled by a state actor to freeze or redirect funds is a liability for its users and its operator.**

---

## 2. The Solution

A non-custodial escrow service where:

1. **Funds are held by a Fedimint federation** — a threshold of independent guardians, no single point of control
2. **Dispute outcomes are decided by a Nostr oracle** — 3 independent arbitrators in different jurisdictions, 2-of-3 threshold, operator is NOT one of them
3. **All payouts are via Lightning Network** — users never see or handle Liquid Bitcoin or on-chain Bitcoin
4. **If the service disappears**, funds are recoverable via timelock escape without any service involvement

### What This Achieves

| Property | How |
|----------|-----|
| Non-custodial | No single party holds funds — Fedimint threshold |
| Operator cannot steal | Operator has no key in the multisig |
| Operator cannot be compelled to freeze | Operator has no key to hand over |
| Dispute resolution is independent | Oracle is separate from fund custody |
| Users only need Lightning | UX is identical to any Lightning payment |
| Censorship resistant | Oracle runs on Nostr — no server to seize |
| Recovery path | Timelock escape after N blocks, no service needed |

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        USER LAYER                           │
│   Buyer (Lightning wallet)    Seller (Lightning wallet)     │
│              │                          │                   │
│              └──────────┬───────────────┘                   │
└─────────────────────────│───────────────────────────────────┘
                          │ Lightning in/out
┌─────────────────────────│───────────────────────────────────┐
│                  SERVICE LAYER (UI only)                    │
│         FastAPI backend + SvelteKit frontend                │
│         Creates deals, tracks status, shows evidence        │
│         NO fund custody, NO dispute decisions               │
└─────────────────────────│───────────────────────────────────┘
                          │ Fedimint client API
┌─────────────────────────│───────────────────────────────────┐
│              FEDIMINT ESCROW MODULE                         │
│                                                             │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │
│   │  Guardian 1 │    │  Guardian 2 │    │  Guardian 3 │   │
│   │ (Frankfurt) │    │  (Helsinki) │    │   (Zurich)  │   │
│   └─────────────┘    └─────────────┘    └─────────────┘   │
│                                                             │
│   Custom Escrow Module:                                     │
│   - Lock ecash on deal creation                             │
│   - Verify oracle attestations                              │
│   - Release/refund via Lightning                            │
│   - Timelock escape for recovery                            │
└─────────────────────────│───────────────────────────────────┘
                          │ Nostr events
┌─────────────────────────│───────────────────────────────────┐
│                   ORACLE LAYER (Nostr)                      │
│                                                             │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │
│   │ Arbitrator 1│    │ Arbitrator 2│    │ Arbitrator 3│   │
│   │  (Nostr key)│    │  (Nostr key)│    │  (Nostr key)│   │
│   └─────────────┘    └─────────────┘    └─────────────┘   │
│                                                             │
│   - Review evidence submitted by parties                    │
│   - Sign outcome as Nostr event (2-of-3 required)          │
│   - Publish to Nostr relay network                          │
│   - No custody, no central server, no single jurisdiction  │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Existing Module Found — Start Here

**Updated finding (February 2026):** We do not need to build the Fedimint escrow module from scratch.

Harsh Pratap Singh built a working Fedimint escrow module during **Summer of Bitcoin 2024**:
- Repository: https://github.com/harsh-ps-2003/escrow
- Cloned locally at: `/home/ralf/fedimint-escrow/`

### What the existing module already has

| Feature | Status |
|---------|--------|
| Three-crate structure (common/server/client) | Done |
| EscrowStates state machine | Done |
| Schnorr signature verification (buyer/seller/arbiter) | Done |
| Secret code mechanism (seller proves delivery) | Done |
| Single arbiter dispute resolution | Done (but single arbiter only) |
| CLI tool and integration tests | Done |
| Database schema (Fedimint patterns) | Done |

### What needs to change for our requirements

| Change | Why |
|--------|-----|
| Replace single `arbiter_pubkey` with `oracle_pubkeys: [PublicKey; 3]` | 2-of-3 Nostr threshold |
| Add 2-of-3 threshold verification to `process_input` | Dispute resolution |
| Add Lightning payout (ecash goes directly to winner now) | UX: users only have LN wallets |
| Add timelock escape path | Recovery if service disappears |
| Fix: `WaitingforBuyerToClaim` returns `seller_pubkey` instead of `buyer_pubkey` | Bug in original code |
| Enable `audit()` (currently commented out) | Federation audit integrity |
| Upgrade from Fedimint v0.3.0 to v0.11.0-alpha | API compatibility |

### Version mismatch

The existing module targets Fedimint tag `v0.3.0`. The current Fedimint main branch is `v0.11.0-alpha`. A `cargo check` on the existing code confirms it fails to compile — one upstream crate (`fs-lock`) has broken compatibility. Fedimint's own module APIs have also evolved significantly. The upgrade effort is the main cost in Phase 1.

---

## 5. High-Level Project Phases

| Phase | Name | Goal | Document |
|-------|------|------|----------|
| 0 | Dev Environment | Fedimint compiles locally, devimint runs | 01_PHASE_0_DEV_ENV.md |
| 1 | Upgrade Existing Module | Fork harsh's module, upgrade to v0.11, fix known issues | 02_PHASE_1_SKELETON.md |
| 2 | Server Additions | LN payout, timelock escape, audit enabled | 03_PHASE_2_SERVER.md |
| 3 | Nostr Oracle | Replace single arbiter with 2-of-3 Nostr threshold | 04_PHASE_3_ORACLE.md |
| 4 | Client Module | Users can create deals, receive LN payouts | 05_PHASE_4_CLIENT.md |
| 5 | Integration | Connect to existing service UI and backend | 06_PHASE_5_INTEGRATION.md |
| 6 | Testing | Full E2E on devimint, edge cases covered | 07_PHASE_6_TESTING.md |
| 7 | Federation Setup | Real guardian nodes deployed, production-ready | 08_PHASE_7_FEDERATION.md |

---

## 5. Key Design Decisions

### 5.1 Why Fedimint (not Liquid multisig)

The current codebase uses Liquid 2-of-3 multisig with pre-signed transactions. This was a reasonable starting point but has a fundamental flaw: the service holds fully-signed transactions and can broadcast them at any time. A regulator can argue this is custody.

Fedimint's threshold cryptography means no signed transaction ever exists on a single machine. Guardians collectively produce signatures through a consensus protocol. No individual guardian — including the service operator — can move funds unilaterally.

### 5.2 Why Nostr for the oracle

Nostr is a censorship-resistant signed-message protocol. An oracle attestation is just a signed Nostr event — it requires no server, no domain, no infrastructure that can be seized. Three arbitrators in three countries each have a keypair. Their 2-of-3 signature on an outcome event is mathematically verifiable by anyone, stored across thousands of relays globally.

### 5.3 Why Lightning for UX

Users interact exclusively with Lightning. They pay a Lightning invoice to fund escrow. They receive a Lightning payment when the deal concludes. Liquid Bitcoin and Fedimint ecash are invisible infrastructure. This is identical UX to any Lightning payment the user already knows.

### 5.4 Operator role (deliberately minimal)

The service operator:
- Runs the UI (SvelteKit frontend)
- Runs the deal coordination API (FastAPI backend)
- Is NOT a Fedimint guardian
- Is NOT an oracle arbitrator
- Holds NO keys that can move funds
- Can be shut down without users losing money

This is the strongest possible legal position: the operator is a software interface, not a financial institution.

---

## 6. What Gets Replaced vs Reused

### Replaced
- Liquid multisig (`multisig_manager.py`)
- Pre-signed transaction logic (`presigned_manager.py`)
- Ephemeral key management (`ephemeral_manager.py`)
- Submarine swap logic (`swaps/`)
- LiquidSigner.js (browser signing)

### Reused
- Deal state machine and API routes (`deals.py`)
- Lightning client (`lightning_client.py`)
- LNURL-auth for user identity (`lnurl_auth.py`)
- SvelteKit frontend (UI and deal flow)
- Deal storage and models (`deal_storage.py`, `models.py`)
- Admin dispute UI

---

## 7. Additional Recommendations

### 7.1 Apply for grants early
This project qualifies for Bitcoin-focused open source grants:
- **OpenSats** — funds Bitcoin/Lightning open source infrastructure
- **HRF (Human Rights Foundation)** — funds privacy/freedom tech
- **Spiral (Block)** — funds Bitcoin developer grants
- **BTCPayServer Foundation** — funds payment infrastructure

Apply once Phase 1 (skeleton) is complete and you can demonstrate a working prototype.

### 7.2 Build in public on Nostr
Document the development process on Nostr. The people who will understand what you're building are on Nostr. Potential arbitrators, potential guardians, potential contributors will find you there. Use the project itself as a case study for why Nostr-based oracles matter.

### 7.3 Arbitrator recruitment strategy
Phase 0 arbitrators = you (3 keypairs, sign all 3 yourself for testing)
Phase 1 arbitrators = trusted technical contacts who understand the system
Phase 2 arbitrators = recruited from the Bitcoin/Nostr/Fedimint community
The social problem is easier to solve once people can see a running system.

### 7.4 Federation guardian strategy
Phase 0 guardians = 4 local devimint instances (your laptop)
Phase 1 guardians = 4 VPS instances you control (different providers)
Phase 2 guardians = independent operators recruited from the community
Start centralised for testing, decentralise progressively.

### 7.5 Consider a staged transition from current codebase
Don't break the existing working system. Run Fedimint escrow in parallel:
- Existing Liquid/presigned flow remains for existing users
- New deals optionally use Fedimint module
- Migrate fully once Fedimint module is battle-tested

---

## 8. Success Criteria

The project is complete when:

1. A buyer can pay a Lightning invoice to fund an escrow
2. A seller can receive a Lightning payment when the deal is released
3. A buyer can receive a Lightning refund when a deal is refunded
4. Dispute resolution happens via 2-of-3 Nostr oracle, without service operator involvement
5. If all service infrastructure is shut down, users can recover funds after the timelock expires
6. The service operator holds no private keys related to user funds
7. The system runs on a real Fedimint federation with independent guardians

---

*Next: See 01_PHASE_0_DEV_ENV.md*
