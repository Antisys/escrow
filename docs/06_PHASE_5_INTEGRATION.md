# Phase 5: Integration with Existing Service

**Goal:** The existing SvelteKit/FastAPI service uses the Fedimint module instead of Liquid.
**Prerequisite:** Phase 4 complete (client module works on devimint)
**Estimated effort:** 1–2 weeks

---

## Context for Claude

The existing codebase (`/home/ralf/ln-escrow/`) is a working escrow service built on Liquid multisig and pre-signed transactions. This phase connects the new Fedimint escrow module to the existing service layer — replacing the Liquid/swap plumbing while keeping the deal UI and API intact.

**Principle: replace the bottom, keep the top.**

The frontend and deal management API remain unchanged. Only the fund-handling layer changes.

---

## What Changes vs What Stays

### Stays unchanged
- `frontend-svelte/` — all UI components, deal flow, LNURL-auth
- `backend/api/routes/deals.py` — deal CRUD, status transitions, WebSocket
- `backend/database/` — deal storage, models
- `backend/auth/` — LNURL-auth, user identity
- `backend/lightning/lightning_client.py` — LND integration

### Replaced
- `backend/vault/` — entire directory (multisig, presigned, ephemeral)
- `backend/swaps/` — entire directory (submarine swaps, Liquid wallet)
- `backend/elements/` — entire directory (Elements/Liquid client)
- `frontend-svelte/src/lib/liquidSigner.js` — browser TX signing (no longer needed)
- `frontend-svelte/src/lib/crypto.js` — ephemeral key management (no longer needed)

### New additions
- `backend/fedimint/` — Fedimint client bridge (Python)
- `backend/fedimint/escrow_client.py` — wraps fedimint-cli or HTTP API
- `backend/fedimint/oracle_listener.py` — monitors Nostr relay for oracle events

---

## Tasks

### Task 5.1 — Create Fedimint client bridge

In `backend/fedimint/escrow_client.py`:

```python
"""
Bridge between FastAPI backend and Fedimint escrow module.
Calls fedimint-cli as a subprocess for Phase 5.
Replace with direct HTTP API or PyO3 bindings in production.
"""
import subprocess, json, logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

FEDIMINT_CLI = "fedimint-cli"  # must be in PATH

@dataclass
class CreateEscrowParams:
    buyer_pubkey: str
    seller_pubkey: str
    amount_msats: int
    conditions_hash: str
    timeout_block: int
    timeout_action: str  # "release" or "refund"

async def create_escrow(params: CreateEscrowParams) -> str:
    """Returns escrow_id on success."""
    result = subprocess.run(
        [FEDIMINT_CLI, "module", "escrow", "create",
         "--buyer-key", params.buyer_pubkey,
         "--seller-key", params.seller_pubkey,
         "--amount", str(params.amount_msats),
         "--conditions-hash", params.conditions_hash,
         "--timeout-block", str(params.timeout_block),
         "--timeout-action", params.timeout_action],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        raise RuntimeError(f"create_escrow failed: {result.stderr}")
    return json.loads(result.stdout)["escrow_id"]

async def release_escrow(escrow_id: str, buyer_sig: str, seller_sig: str, invoice: str) -> str:
    """Returns txid on success."""
    result = subprocess.run(
        [FEDIMINT_CLI, "module", "escrow", "release",
         "--escrow-id", escrow_id,
         "--buyer-sig", buyer_sig,
         "--seller-sig", seller_sig,
         "--invoice", invoice],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        raise RuntimeError(f"release_escrow failed: {result.stderr}")
    return json.loads(result.stdout)["txid"]

async def refund_escrow(escrow_id: str, buyer_sig: str, seller_sig: str, invoice: str) -> str:
    """Returns txid on success."""
    # Mirror of release with refund endpoint
    pass

async def oracle_resolve(escrow_id: str, attestations: list, invoice: str) -> str:
    """Resolve escrow via oracle attestations."""
    pass
```

---

### Task 5.2 — Replace vault calls in deals.py

Find all calls to vault/swap functions in `backend/api/routes/deals.py` and replace:

| Old call | New call |
|----------|----------|
| `vault_service.create_vault()` | `escrow_client.create_escrow()` |
| `presigned_manager.broadcast_presigned_release()` | `escrow_client.release_escrow()` |
| `presigned_manager.broadcast_presigned_refund()` | `escrow_client.refund_escrow()` |
| `swap_service.fund_from_ln()` | Fedimint handles LN funding natively |
| `ephemeral_manager.register_pubkey()` | Fedimint client manages keys |

The deal status machine (pending → funded → shipped → completed) stays unchanged.

---

### Task 5.3 — Replace signing flow in frontend

The current frontend (`frontend-svelte/src/lib/liquidSigner.js`) signs Liquid transactions in the browser. This is no longer needed.

Replace the signing step with:
1. Frontend generates a secp256k1 keypair (using `@noble/secp256k1`, already a dependency)
2. Frontend registers pubkey with backend (existing LNURL-auth flow)
3. At deal creation/join, frontend signs a simple message (not a full TX) using its key
4. Backend submits the signature to the Fedimint module

The browser never builds a Liquid transaction again.

Update `frontend-svelte/src/lib/crypto.js`:
```javascript
// Replace liquidSigner with simple message signing
export async function signEscrowMessage(privateKeyHex, message) {
    const { sign } = await import('@noble/secp256k1')
    const msgHash = sha256(new TextEncoder().encode(message))
    const sig = await sign(msgHash, privateKeyHex)
    return sig.toDERHex()
}
```

---

### Task 5.4 — Implement Nostr oracle listener

The service needs to watch for oracle attestation events on Nostr relays.

In `backend/fedimint/oracle_listener.py`:

```python
"""
Monitors Nostr relays for oracle attestation events (kind 30001).
When 2-of-3 oracle signatures are found for a disputed deal,
triggers the oracle_resolve flow automatically.
"""
import asyncio, json, websockets
from backend.fedimint.escrow_client import oracle_resolve

NOSTR_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
]

ORACLE_PUBKEYS = [
    # Loaded from config — the 3 arbitrator pubkeys
]

async def listen_for_attestations(deal_id: str, escrow_id: str, invoice: str):
    """
    Subscribe to Nostr relay for oracle events related to this escrow.
    Resolves when 2-of-3 signatures are collected.
    """
    attestations = {}

    for relay_url in NOSTR_RELAYS:
        async with websockets.connect(relay_url) as ws:
            # Subscribe to oracle attestation events for this escrow
            sub_filter = {
                "kinds": [30001],
                "authors": ORACLE_PUBKEYS,
                "#d": [escrow_id],
            }
            await ws.send(json.dumps(["REQ", "oracle-sub", sub_filter]))

            async for msg in ws:
                event_type, _, event = json.loads(msg)
                if event_type != "EVENT":
                    continue

                pubkey = event["pubkey"]
                if pubkey not in attestations:
                    attestations[pubkey] = event

                if len(attestations) >= 2:
                    # We have 2-of-3 — trigger resolution
                    await oracle_resolve(
                        escrow_id,
                        list(attestations.values()),
                        invoice
                    )
                    return
```

---

### Task 5.5 — Update database models

Add `escrow_id` (Fedimint escrow ID) to the `deals` table alongside the existing deal structure.

```python
# In backend/database/models.py, add to Deal model:
fedimint_escrow_id = Column(String, nullable=True)
fedimint_federation_id = Column(String, nullable=True)
```

Database migration on Pi:
```bash
ssh pi@192.168.1.111 "cd /home/pi/ln-escrow && venv/bin/python3 -c \"
import sqlite3
conn = sqlite3.connect('/home/pi/.ln-escrow/escrow.db')
c = conn.cursor()
c.execute('ALTER TABLE deals ADD COLUMN fedimint_escrow_id TEXT')
c.execute('ALTER TABLE deals ADD COLUMN fedimint_federation_id TEXT')
conn.commit()
conn.close()
\""
```

---

### Task 5.6 — Remove Liquid/swap dependencies

Once Fedimint integration is confirmed working, remove:
- `pip uninstall python-elementstx coincurve` (from backend/requirements.txt)
- Delete `backend/vault/`, `backend/swaps/`, `backend/elements/`
- Delete `frontend-svelte/src/lib/liquidSigner.js`
- Remove Liquid-related env vars from `.env`

Do this last — keep the old code around until the new path is fully tested.

---

## Definition of Done

- [ ] `backend/fedimint/escrow_client.py` bridges to fedimint-cli
- [ ] `deals.py` calls Fedimint client instead of vault/swap code
- [ ] Frontend no longer signs Liquid transactions
- [ ] Frontend key management uses simple message signing
- [ ] Nostr oracle listener detects 2-of-3 attestations and triggers resolution
- [ ] `fedimint_escrow_id` column added to deals table
- [ ] Full deal flow works end-to-end on devimint:
  - Buyer pays LN → escrow created
  - Seller marks shipped → buyer releases
  - Seller receives LN payout
- [ ] Dispute flow works:
  - Dispute raised → oracle listener starts
  - 2 attestations received → oracle_resolve called
  - Winner receives LN payout

---

*Next: See 07_PHASE_6_TESTING.md*
