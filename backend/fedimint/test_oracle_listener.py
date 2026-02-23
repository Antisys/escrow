"""
Unit tests for OracleListener.

No real Nostr relays needed — WebSocket connections are mocked.
Run with: pytest backend/fedimint/test_oracle_listener.py -v
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.fedimint.oracle_listener import (
    ORACLE_ATTESTATION_KIND,
    OracleListener,
    _Accumulator,
    _compressed_from_xonly,
    _parse_nostr_event,
    _xonly_from_compressed,
)
from backend.fedimint.escrow_client import SignedAttestation

# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

# Compressed pubkeys (33 bytes = 66 hex chars, even parity)
ORACLE_1 = "02" + "aa" * 32
ORACLE_2 = "02" + "bb" * 32
ORACLE_3 = "02" + "cc" * 32
ORACLE_PUBKEYS = [ORACLE_1, ORACLE_2, ORACLE_3]

XONLY_1 = "aa" * 32
XONLY_2 = "bb" * 32
XONLY_3 = "cc" * 32
REGISTERED_XONLY = {XONLY_1, XONLY_2, XONLY_3}

ESCROW_ID = "testEscrow001"
SIG = "dd" * 64  # 128 hex chars


def make_event(xonly_pubkey: str, outcome: str, escrow_id: str = ESCROW_ID, sig: str = SIG) -> dict:
    return {
        "id": "ee" * 32,
        "pubkey": xonly_pubkey,
        "created_at": 1_700_000_000,
        "kind": ORACLE_ATTESTATION_KIND,
        "tags": [["d", escrow_id]],
        "content": outcome,
        "sig": sig,
    }


# ---------------------------------------------------------------------------
# pubkey conversion helpers
# ---------------------------------------------------------------------------

def test_xonly_from_compressed():
    assert _xonly_from_compressed("02" + "ab" * 32) == "ab" * 32
    assert _xonly_from_compressed("03" + "cd" * 32) == "cd" * 32


def test_compressed_from_xonly():
    assert _compressed_from_xonly("ab" * 32) == "02" + "ab" * 32


def test_xonly_roundtrip():
    compressed = "02" + "aa" * 32
    assert _compressed_from_xonly(_xonly_from_compressed(compressed)) == compressed


# ---------------------------------------------------------------------------
# _parse_nostr_event
# ---------------------------------------------------------------------------

def test_parse_valid_buyer_event():
    event = make_event(XONLY_1, "buyer")
    result = _parse_nostr_event(event, REGISTERED_XONLY, ESCROW_ID)
    assert result is not None
    xonly, att = result
    assert xonly == XONLY_1
    assert att.pubkey == ORACLE_1
    assert att.signature == SIG
    assert att.content["outcome"] == "buyer"
    assert att.content["escrow_id"] == ESCROW_ID


def test_parse_valid_seller_event():
    event = make_event(XONLY_2, "seller")
    result = _parse_nostr_event(event, REGISTERED_XONLY, ESCROW_ID)
    assert result is not None
    _, att = result
    assert att.content["outcome"] == "seller"


def test_parse_unknown_oracle_returns_none():
    unknown = "ff" * 32
    event = make_event(unknown, "buyer")
    assert _parse_nostr_event(event, REGISTERED_XONLY, ESCROW_ID) is None


def test_parse_wrong_escrow_id_returns_none():
    event = make_event(XONLY_1, "buyer", escrow_id="other-escrow")
    assert _parse_nostr_event(event, REGISTERED_XONLY, ESCROW_ID) is None


def test_parse_wrong_kind_returns_none():
    event = make_event(XONLY_1, "buyer")
    event["kind"] = 1  # plain note, not attestation
    assert _parse_nostr_event(event, REGISTERED_XONLY, ESCROW_ID) is None


def test_parse_invalid_outcome_returns_none():
    event = make_event(XONLY_1, "nobody")
    assert _parse_nostr_event(event, REGISTERED_XONLY, ESCROW_ID) is None


def test_parse_missing_d_tag_returns_none():
    event = make_event(XONLY_1, "buyer")
    event["tags"] = []  # no 'd' tag
    assert _parse_nostr_event(event, REGISTERED_XONLY, ESCROW_ID) is None


# ---------------------------------------------------------------------------
# _Accumulator
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_accumulator_resolves_on_threshold():
    acc = _Accumulator(escrow_id=ESCROW_ID)

    att1 = SignedAttestation(pubkey=ORACLE_1, signature=SIG,
                             content={"escrow_id": ESCROW_ID, "outcome": "buyer", "decided_at": 1})
    att2 = SignedAttestation(pubkey=ORACLE_2, signature=SIG,
                             content={"escrow_id": ESCROW_ID, "outcome": "buyer", "decided_at": 2})

    await acc.add(XONLY_1, att1)
    assert not acc.resolved.is_set()

    await acc.add(XONLY_2, att2)
    assert acc.resolved.is_set()


@pytest.mark.asyncio
async def test_accumulator_conflicting_outcomes_no_resolve():
    acc = _Accumulator(escrow_id=ESCROW_ID)

    att1 = SignedAttestation(pubkey=ORACLE_1, signature=SIG,
                             content={"escrow_id": ESCROW_ID, "outcome": "buyer", "decided_at": 1})
    att2 = SignedAttestation(pubkey=ORACLE_2, signature=SIG,
                             content={"escrow_id": ESCROW_ID, "outcome": "seller", "decided_at": 2})

    await acc.add(XONLY_1, att1)
    await acc.add(XONLY_2, att2)
    # 1 buyer + 1 seller — threshold not met
    assert not acc.resolved.is_set()


@pytest.mark.asyncio
async def test_accumulator_deduplicates_same_oracle():
    acc = _Accumulator(escrow_id=ESCROW_ID)

    att = SignedAttestation(pubkey=ORACLE_1, signature=SIG,
                            content={"escrow_id": ESCROW_ID, "outcome": "buyer", "decided_at": 1})
    await acc.add(XONLY_1, att)
    await acc.add(XONLY_1, att)  # duplicate — should be ignored
    assert len(acc.by_pubkey) == 1
    assert not acc.resolved.is_set()


@pytest.mark.asyncio
async def test_accumulator_winning_attestations():
    acc = _Accumulator(escrow_id=ESCROW_ID)

    att1 = SignedAttestation(pubkey=ORACLE_1, signature=SIG,
                             content={"escrow_id": ESCROW_ID, "outcome": "seller", "decided_at": 1})
    att2 = SignedAttestation(pubkey=ORACLE_2, signature=SIG,
                             content={"escrow_id": ESCROW_ID, "outcome": "seller", "decided_at": 2})
    await acc.add(XONLY_1, att1)
    await acc.add(XONLY_2, att2)

    winners = acc.winning_attestations()
    assert len(winners) == 2
    assert all(a.content["outcome"] == "seller" for a in winners)


# ---------------------------------------------------------------------------
# OracleListener integration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_watch_escrow_calls_callback_on_threshold():
    """Simulate two oracle events arriving and verify the callback fires."""
    listener = OracleListener(
        relays=["wss://test.relay"],
        oracle_pubkeys=ORACLE_PUBKEYS,
    )

    resolved_escrow_ids = []
    resolved_attestations = []

    async def on_resolved(escrow_id, attestations):
        resolved_escrow_ids.append(escrow_id)
        resolved_attestations.extend(attestations)

    # Patch _listen_one_relay to inject two agreeing events directly into
    # the accumulator, then let it complete.
    async def fake_relay(relay_url, escrow_id, registered_xonly, accumulator, stop_event):
        att1 = SignedAttestation(
            pubkey=ORACLE_1, signature=SIG,
            content={"escrow_id": escrow_id, "outcome": "buyer", "decided_at": 1},
        )
        att2 = SignedAttestation(
            pubkey=ORACLE_2, signature=SIG,
            content={"escrow_id": escrow_id, "outcome": "buyer", "decided_at": 2},
        )
        await accumulator.add(XONLY_1, att1)
        await accumulator.add(XONLY_2, att2)
        # Wait until stop is requested
        await stop_event.wait()

    with patch("backend.fedimint.oracle_listener._listen_one_relay", side_effect=fake_relay):
        await listener.watch_escrow(ESCROW_ID, ORACLE_PUBKEYS, on_resolved)
        # Give the task time to run
        await asyncio.sleep(0.05)

    assert resolved_escrow_ids == [ESCROW_ID]
    assert len(resolved_attestations) == 2
    assert all(a.content["outcome"] == "buyer" for a in resolved_attestations)


@pytest.mark.asyncio
async def test_watch_escrow_stop_watching():
    """Stopping a watch before threshold is reached cancels the task cleanly."""
    listener = OracleListener(
        relays=["wss://test.relay"],
        oracle_pubkeys=ORACLE_PUBKEYS,
    )

    async def on_resolved(escrow_id, attestations):
        pytest.fail("on_resolved should not be called")

    async def fake_relay(relay_url, escrow_id, registered_xonly, accumulator, stop_event):
        await stop_event.wait()

    with patch("backend.fedimint.oracle_listener._listen_one_relay", side_effect=fake_relay):
        await listener.watch_escrow(ESCROW_ID, ORACLE_PUBKEYS, on_resolved)
        assert ESCROW_ID in listener.active_escrows
        listener.stop_watching(ESCROW_ID)
        # stop_watching clears the dict synchronously — no yield needed

    assert ESCROW_ID not in listener.active_escrows


@pytest.mark.asyncio
async def test_watch_escrow_duplicate_ignored():
    """Calling watch_escrow twice for the same escrow_id does not create two tasks."""
    listener = OracleListener(relays=["wss://test.relay"], oracle_pubkeys=ORACLE_PUBKEYS)

    async def fake_relay(*args, **kwargs):
        await asyncio.sleep(10)

    async def on_resolved(escrow_id, attestations):
        pass

    with patch("backend.fedimint.oracle_listener._listen_one_relay", side_effect=fake_relay):
        await listener.watch_escrow(ESCROW_ID, ORACLE_PUBKEYS, on_resolved)
        await listener.watch_escrow(ESCROW_ID, ORACLE_PUBKEYS, on_resolved)
        assert len(listener.active_escrows) == 1

    await listener.stop_all()


@pytest.mark.asyncio
async def test_stop_all_clears_tasks():
    """stop_all() cancels all active tasks."""
    listener = OracleListener(relays=["wss://r1", "wss://r2"], oracle_pubkeys=ORACLE_PUBKEYS)

    async def fake_relay(*args, **kwargs):
        await asyncio.sleep(10)

    async def on_resolved(*args):
        pass

    with patch("backend.fedimint.oracle_listener._listen_one_relay", side_effect=fake_relay):
        await listener.watch_escrow("escrow-A", ORACLE_PUBKEYS, on_resolved)
        await listener.watch_escrow("escrow-B", ORACLE_PUBKEYS, on_resolved)
        assert len(listener.active_escrows) == 2
        await listener.stop_all()
        assert listener.active_escrows == []
