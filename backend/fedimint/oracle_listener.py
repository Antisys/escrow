"""
Nostr Oracle Listener
======================
Monitors Nostr relays for oracle attestation events (kind 30001).
When 2-of-3 registered oracle pubkeys agree on an outcome for a disputed
escrow, calls the provided callback with the collected SignedAttestations.

Configuration (via environment variables):
  NOSTR_RELAYS      Comma-separated list of relay URLs
                    Default: wss://relay.damus.io,wss://nos.lol,wss://relay.nostr.band
  ORACLE_PUBKEYS    Comma-separated hex pubkeys of the 3 registered oracles
                    (compressed, 33 bytes = 66 hex chars)

Typical usage:
    from backend.fedimint.oracle_listener import OracleListener
    from backend.fedimint.escrow_client import EscrowClient

    client = EscrowClient()
    listener = OracleListener()

    async def on_resolved(escrow_id, attestations):
        await client.resolve_via_oracle(escrow_id, attestations)

    # Start watching when a dispute is raised
    await listener.watch_escrow("my-escrow-id", oracle_pubkeys, on_resolved)

    # Stop watching when escrow is resolved or service shuts down
    listener.stop_watching("my-escrow-id")
    await listener.stop_all()
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Optional

from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed, WebSocketException

from backend.fedimint.escrow_client import SignedAttestation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ORACLE_ATTESTATION_KIND = 30_001
RECONNECT_DELAY_SECONDS = 5.0
THRESHOLD = 2  # 2-of-3 oracles must agree

DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
]

# Callback type: async fn(escrow_id, attestations) -> None
OnResolvedCallback = Callable[[str, list[SignedAttestation]], Awaitable[None]]


# ---------------------------------------------------------------------------
# Attestation accumulator
# ---------------------------------------------------------------------------

@dataclass
class _Accumulator:
    """
    Thread-safe (asyncio) accumulator for oracle attestations for one escrow.

    Deduplicates by oracle pubkey (first valid attestation per oracle wins).
    Signals `resolved` event when THRESHOLD agreeing attestations are collected.
    """
    escrow_id: str
    # xonly_pubkey_hex → SignedAttestation
    by_pubkey: dict[str, SignedAttestation] = field(default_factory=dict)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    resolved: asyncio.Event = field(default_factory=asyncio.Event)

    async def add(self, xonly_pubkey: str, attestation: SignedAttestation) -> None:
        async with self.lock:
            if xonly_pubkey in self.by_pubkey:
                return  # already have this oracle's vote
            if self.resolved.is_set():
                return  # already resolved
            self.by_pubkey[xonly_pubkey] = attestation
            logger.info(
                "escrow=%s oracle=%s...%s voted %s (%d/%d)",
                self.escrow_id, xonly_pubkey[:8], xonly_pubkey[-4:],
                attestation.content.get("outcome", "?"),
                len(self.by_pubkey), THRESHOLD,
            )
            if self._check_threshold():
                self.resolved.set()

    def _check_threshold(self) -> bool:
        """Return True if THRESHOLD attestations agree on the same outcome."""
        counts: dict[str, int] = {}
        for att in self.by_pubkey.values():
            outcome = att.content.get("outcome", "")
            counts[outcome] = counts.get(outcome, 0) + 1
        return any(c >= THRESHOLD for c in counts.values())

    def winning_attestations(self) -> list[SignedAttestation]:
        """Return the attestations for the majority outcome."""
        counts: dict[str, list[SignedAttestation]] = {}
        for att in self.by_pubkey.values():
            outcome = att.content.get("outcome", "")
            counts.setdefault(outcome, []).append(att)
        # Return the group that reached threshold
        for atts in counts.values():
            if len(atts) >= THRESHOLD:
                return atts
        return []


# ---------------------------------------------------------------------------
# Nostr event parsing
# ---------------------------------------------------------------------------

def _xonly_from_compressed(compressed_pubkey_hex: str) -> str:
    """
    Convert a compressed secp256k1 pubkey (66 hex chars) to x-only (64 hex chars).
    Strips the 02/03 prefix.
    """
    if len(compressed_pubkey_hex) != 66:
        raise ValueError(f"Expected 66-char compressed pubkey, got {len(compressed_pubkey_hex)}")
    return compressed_pubkey_hex[2:]  # drop 02/03 prefix


def _compressed_from_xonly(xonly_hex: str) -> str:
    """
    Reconstruct a compressed pubkey from an x-only pubkey.
    Nostr normalises to even parity, so we prepend 02.
    """
    if len(xonly_hex) != 64:
        raise ValueError(f"Expected 64-char x-only pubkey, got {len(xonly_hex)}")
    return "02" + xonly_hex


def _parse_nostr_event(
    event: dict,
    registered_xonly: set[str],
    escrow_id: str,
) -> Optional[tuple[str, SignedAttestation]]:
    """
    Parse a raw Nostr event dict into a (xonly_pubkey, SignedAttestation) pair.

    Returns None if the event is not a valid oracle attestation for this escrow.
    Does NOT verify the Schnorr signature — the federation does that on submission.
    """
    try:
        kind = event.get("kind")
        if kind != ORACLE_ATTESTATION_KIND:
            return None

        xonly_pubkey: str = event["pubkey"]
        if xonly_pubkey not in registered_xonly:
            logger.debug("Ignoring event from unknown oracle %s...", xonly_pubkey[:8])
            return None

        # Extract escrow_id from the 'd' tag
        d_tag_value = next(
            (tag[1] for tag in event.get("tags", []) if len(tag) >= 2 and tag[0] == "d"),
            None,
        )
        if d_tag_value != escrow_id:
            return None  # Not for this escrow

        outcome = event.get("content", "").strip().lower()
        if outcome not in ("buyer", "seller"):
            logger.warning("Unknown outcome %r in oracle event", outcome)
            return None

        decided_at: int = event["created_at"]
        signature: str = event["sig"]
        reason: Optional[str] = None

        # Optional: reason may be embedded as a JSON field in content
        try:
            parsed_content = json.loads(event["content"])
            if isinstance(parsed_content, dict):
                outcome = parsed_content.get("outcome", outcome)
                reason = parsed_content.get("reason")
        except (json.JSONDecodeError, KeyError):
            pass  # content is plain "buyer"/"seller" string — that's fine

        compressed_pubkey = _compressed_from_xonly(xonly_pubkey)

        attestation = SignedAttestation(
            pubkey=compressed_pubkey,
            signature=signature,
            content={
                "escrow_id": escrow_id,
                "outcome": outcome,
                "decided_at": decided_at,
                **({"reason": reason} if reason else {}),
            },
        )
        return xonly_pubkey, attestation

    except (KeyError, TypeError, ValueError) as exc:
        logger.debug("Malformed Nostr event: %s (%s)", exc, event.get("id", "?"))
        return None


# ---------------------------------------------------------------------------
# Per-relay coroutine
# ---------------------------------------------------------------------------

async def _listen_one_relay(
    relay_url: str,
    escrow_id: str,
    registered_xonly: set[str],
    accumulator: _Accumulator,
    stop_event: asyncio.Event,
) -> None:
    """
    Connect to a single Nostr relay and stream oracle attestation events
    until stop_event is set or the accumulator resolves.

    Reconnects on connection errors with exponential backoff.
    """
    sub_id = f"oracle-{escrow_id[:8]}"
    req = json.dumps([
        "REQ",
        sub_id,
        {
            "kinds": [ORACLE_ATTESTATION_KIND],
            "authors": list(registered_xonly),
            "#d": [escrow_id],
        },
    ])

    delay = RECONNECT_DELAY_SECONDS
    while not stop_event.is_set() and not accumulator.resolved.is_set():
        try:
            async with ws_connect(relay_url, open_timeout=10) as ws:
                logger.info("Connected to relay %s for escrow %s", relay_url, escrow_id)
                delay = RECONNECT_DELAY_SECONDS  # reset on successful connect
                await ws.send(req)

                while not stop_event.is_set() and not accumulator.resolved.is_set():
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=30)
                    except asyncio.TimeoutError:
                        # Send a ping to keep the connection alive
                        await ws.send(json.dumps(["PING"]))
                        continue

                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    if not isinstance(msg, list) or len(msg) < 2:
                        continue

                    msg_type = msg[0]

                    if msg_type == "EVENT" and len(msg) >= 3:
                        _sub_id, event = msg[1], msg[2]
                        parsed = _parse_nostr_event(event, registered_xonly, escrow_id)
                        if parsed:
                            xonly, attestation = parsed
                            await accumulator.add(xonly, attestation)

                    elif msg_type == "EOSE":
                        # End of stored events — we're now receiving live events
                        logger.debug("relay=%s EOSE for escrow %s", relay_url, escrow_id)

                    elif msg_type == "NOTICE":
                        logger.debug("relay=%s NOTICE: %s", relay_url, msg[1] if len(msg) > 1 else "")

        except (ConnectionClosed, WebSocketException, OSError, asyncio.TimeoutError) as exc:
            if stop_event.is_set() or accumulator.resolved.is_set():
                break
            logger.warning(
                "relay=%s lost connection (%s), retrying in %.0fs",
                relay_url, exc, delay,
            )
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)  # exponential backoff, max 60s


# ---------------------------------------------------------------------------
# Main OracleListener
# ---------------------------------------------------------------------------

class OracleListener:
    """
    Manages per-escrow Nostr oracle watch tasks.

    Spawns one asyncio Task per escrow being watched.
    Each task fans out to N relay coroutines concurrently.
    """

    def __init__(
        self,
        relays: Optional[list[str]] = None,
        oracle_pubkeys: Optional[list[str]] = None,
    ):
        env_relays = os.environ.get("NOSTR_RELAYS", "")
        self.relays: list[str] = (
            relays
            or [r.strip() for r in env_relays.split(",") if r.strip()]
            or DEFAULT_RELAYS
        )

        env_keys = os.environ.get("ORACLE_PUBKEYS", "")
        self.oracle_pubkeys: list[str] = (
            oracle_pubkeys
            or [k.strip() for k in env_keys.split(",") if k.strip()]
        )

        # escrow_id → asyncio.Task
        self._tasks: dict[str, asyncio.Task] = {}
        # escrow_id → stop event
        self._stop_events: dict[str, asyncio.Event] = {}

    async def watch_escrow(
        self,
        escrow_id: str,
        oracle_pubkeys: Optional[list[str]],
        on_resolved: OnResolvedCallback,
    ) -> None:
        """
        Start watching for oracle attestations for the given escrow.

        Args:
            escrow_id:      The escrow to watch
            oracle_pubkeys: The 3 registered oracle pubkeys for this escrow
                            (compressed hex). Falls back to self.oracle_pubkeys.
            on_resolved:    Async callback called with (escrow_id, attestations)
                            when 2-of-3 oracles agree. Called exactly once.
        """
        if escrow_id in self._tasks:
            logger.warning("Already watching escrow %s", escrow_id)
            return

        pubkeys = oracle_pubkeys or self.oracle_pubkeys
        if not pubkeys:
            raise ValueError("No oracle pubkeys configured")

        registered_xonly = {_xonly_from_compressed(pk) for pk in pubkeys}

        stop_event = asyncio.Event()
        accumulator = _Accumulator(escrow_id=escrow_id)

        task = asyncio.create_task(
            self._watch_task(escrow_id, registered_xonly, accumulator, stop_event, on_resolved),
            name=f"oracle-watch-{escrow_id[:12]}",
        )
        self._tasks[escrow_id] = task
        self._stop_events[escrow_id] = stop_event
        logger.info("Started oracle watch for escrow %s on %d relays", escrow_id, len(self.relays))

    async def _watch_task(
        self,
        escrow_id: str,
        registered_xonly: set[str],
        accumulator: _Accumulator,
        stop_event: asyncio.Event,
        on_resolved: OnResolvedCallback,
    ) -> None:
        """Internal task: fan out to all relays, fire callback on threshold."""
        relay_tasks = [
            asyncio.create_task(
                _listen_one_relay(relay_url, escrow_id, registered_xonly, accumulator, stop_event),
                name=f"relay-{relay_url.split('//')[1].split('/')[0]}-{escrow_id[:8]}",
            )
            for relay_url in self.relays
        ]

        try:
            # Wait until resolved or stopped
            await accumulator.resolved.wait()

            if not stop_event.is_set():
                attestations = accumulator.winning_attestations()
                logger.info(
                    "escrow=%s threshold reached (%d attestations), calling on_resolved",
                    escrow_id, len(attestations),
                )
                try:
                    await on_resolved(escrow_id, attestations)
                except Exception as exc:
                    logger.error("on_resolved callback failed for escrow %s: %s", escrow_id, exc)
        finally:
            # All cleanup is synchronous — no await — so a CancelledError cannot
            # interrupt it and leave the dicts in a dirty state.
            self._tasks.pop(escrow_id, None)
            self._stop_events.pop(escrow_id, None)
            stop_event.set()
            for t in relay_tasks:
                t.cancel()

    def stop_watching(self, escrow_id: str) -> None:
        """Cancel the watch task for the given escrow (non-blocking).

        Clears the tracking dicts immediately so active_escrows reflects the
        removal at once — even if the task's coroutine hasn't started yet.
        (In Python 3.12, a task cancelled before its first step never runs
        its body, so relying on the finally-block for cleanup is not safe.)
        """
        stop_event = self._stop_events.pop(escrow_id, None)
        if stop_event:
            stop_event.set()
        task = self._tasks.pop(escrow_id, None)
        if task:
            task.cancel()

    async def stop_all(self) -> None:
        """Cancel all active watch tasks and wait for them to finish."""
        # Snapshot and clear synchronously first
        tasks = list(self._tasks.values())
        stop_events = list(self._stop_events.values())
        self._tasks.clear()
        self._stop_events.clear()
        for stop_event in stop_events:
            stop_event.set()
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    @property
    def active_escrows(self) -> list[str]:
        """List of escrow IDs currently being watched."""
        return list(self._tasks.keys())
