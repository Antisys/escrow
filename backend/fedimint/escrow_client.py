"""
Fedimint Escrow Client Bridge
==============================
Wraps fedimint-cli module escrow <command> as async subprocess calls.

All public functions are async. Errors raise EscrowClientError.

Configuration (via environment variables):
  FEDIMINT_CLI_PATH   Path to the fedimint-cli binary (default: "fedimint-cli")
  FEDIMINT_DATA_DIR   Client data directory passed as --data-dir (default: ~/.config/fedimint-client)
  FEDIMINT_PASSWORD   Client password passed as --password (optional)

Typical usage:
    from backend.fedimint.escrow_client import EscrowClient

    client = EscrowClient()
    result = await client.create_escrow(
        seller_pubkey="02abcd...",
        oracle_pubkeys=["02aa...", "02bb...", "02cc..."],
        amount_sats=100_000,
        timeout_block=900_000,
        timeout_action="refund",
    )
    print(result.escrow_id, result.secret_code)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class EscrowClientError(Exception):
    """Raised when a fedimint-cli call fails."""
    def __init__(self, message: str, stderr: str = ""):
        super().__init__(message)
        self.stderr = stderr


class EscrowNotFoundError(EscrowClientError):
    pass


class EscrowStateError(EscrowClientError):
    """Raised when the escrow is in the wrong state for the requested operation."""
    pass


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class CreateEscrowResult:
    escrow_id: str
    secret_code: str


@dataclass
class EscrowInfo:
    escrow_id: str
    buyer_pubkey: str
    seller_pubkey: str
    oracle_pubkeys: list[str]
    amount: dict          # Fedimint Amount object {"msats": N}
    state: str
    timeout_block: int
    timeout_action: str


@dataclass
class SignedAttestation:
    """A single oracle attestation, matching the format of oracle_sign.py output."""
    pubkey: str
    signature: str
    content: dict         # {escrow_id, outcome, decided_at, reason?}


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class EscrowClient:
    """
    Async wrapper around `fedimint-cli module escrow`.

    All methods raise EscrowClientError on failure.
    """

    def __init__(
        self,
        cli_path: Optional[str] = None,
        data_dir: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.cli_path = cli_path or os.environ.get("FEDIMINT_CLI_PATH", "fedimint-cli")
        self.data_dir = data_dir or os.environ.get("FEDIMINT_DATA_DIR")
        self.password = password or os.environ.get("FEDIMINT_PASSWORD")

    # ------------------------------------------------------------------
    # Low-level subprocess helper
    # ------------------------------------------------------------------

    async def _run(self, *args: str) -> dict:
        """
        Run: fedimint-cli [--data-dir ...] [--password ...] <args...>
        Returns parsed JSON stdout on success.
        Raises EscrowClientError on non-zero exit or JSON parse failure.
        """
        cmd = [self.cli_path]
        if self.data_dir:
            cmd += ["--data-dir", self.data_dir]
        if self.password:
            cmd += ["--password", self.password]
        cmd += list(args)

        logger.debug("fedimint-cli: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        stdout_str = stdout.decode().strip()
        stderr_str = stderr.decode().strip()

        if proc.returncode != 0:
            logger.error("fedimint-cli failed (rc=%d): %s", proc.returncode, stderr_str)
            # Surface user-friendly error messages where we can recognise them
            if "EscrowNotFound" in stderr_str or "escrow not found" in stderr_str.lower():
                raise EscrowNotFoundError(f"Escrow not found", stderr=stderr_str)
            if "EscrowDisputed" in stderr_str:
                raise EscrowStateError("Escrow is disputed", stderr=stderr_str)
            if "InvalidStateFor" in stderr_str:
                raise EscrowStateError(f"Invalid escrow state: {stderr_str}", stderr=stderr_str)
            raise EscrowClientError(
                f"fedimint-cli {' '.join(args[:3])} failed (rc={proc.returncode}): {stderr_str}",
                stderr=stderr_str,
            )

        if not stdout_str:
            return {}

        try:
            return json.loads(stdout_str)
        except json.JSONDecodeError as e:
            raise EscrowClientError(
                f"fedimint-cli returned non-JSON output: {stdout_str!r}",
                stderr=stderr_str,
            ) from e

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def create_escrow(
        self,
        seller_pubkey: str,
        oracle_pubkeys: list[str],
        amount_sats: int,
        timeout_block: int,
        timeout_action: str = "refund",
    ) -> CreateEscrowResult:
        """
        Lock funds in a new escrow.

        The federation generates the escrow_id and secret_code internally.
        The caller must share secret_code with the seller off-band.

        Args:
            seller_pubkey:    Seller's secp256k1 pubkey (hex, compressed)
            oracle_pubkeys:   Exactly 3 oracle pubkeys (hex, compressed)
            amount_sats:      Escrow amount in satoshis
            timeout_block:    Bitcoin block height after which timeout escape is available
            timeout_action:   "refund" (buyer reclaims) or "release" (seller claims) on timeout

        Returns:
            CreateEscrowResult with escrow_id and secret_code
        """
        if len(oracle_pubkeys) != 3:
            raise EscrowClientError("oracle_pubkeys must contain exactly 3 pubkeys")

        # Amount in msats (Fedimint uses msat representation as "N msat" string)
        amount_str = f"{amount_sats * 1000} msat"

        data = await self._run(
            "module", "escrow", "create",
            seller_pubkey,
            oracle_pubkeys[0],
            oracle_pubkeys[1],
            oracle_pubkeys[2],
            amount_str,
            str(timeout_block),
            timeout_action,
        )

        return CreateEscrowResult(
            escrow_id=data["escrow-id"],
            secret_code=data["secret-code"],
        )

    async def get_escrow_info(self, escrow_id: str) -> EscrowInfo:
        """
        Fetch current escrow state from the federation.

        Raises EscrowNotFoundError if the escrow_id is unknown.
        """
        data = await self._run("module", "escrow", "info", escrow_id)

        return EscrowInfo(
            escrow_id=escrow_id,
            buyer_pubkey=data["buyer_pubkey"],
            seller_pubkey=data["seller_pubkey"],
            oracle_pubkeys=data.get("oracle_pubkeys", []),
            amount=data["amount"],
            state=data["state"],
            timeout_block=data["timeout_block"],
            timeout_action=data["timeout_action"],
        )

    async def claim_escrow(self, escrow_id: str, secret_code: str) -> None:
        """
        Cooperative release: seller claims funds using the secret code.

        Only valid when escrow is in Open state.
        Raises EscrowStateError if disputed or already resolved.
        """
        await self._run("module", "escrow", "claim", escrow_id, secret_code)

    async def initiate_dispute(self, escrow_id: str) -> None:
        """
        Raise a dispute on an escrow (buyer or seller).

        Transitions escrow to DisputedByBuyer or DisputedBySeller.
        """
        await self._run("module", "escrow", "dispute", escrow_id)

    async def resolve_via_oracle(
        self,
        escrow_id: str,
        attestations: list[SignedAttestation],
    ) -> None:
        """
        Resolve a disputed escrow using 2-of-3 oracle attestations.

        Attestations should be collected from oracle_sign.py or the Nostr oracle listener.
        The federation verifies the threshold and pays the winner.

        Args:
            escrow_id:     The disputed escrow to resolve
            attestations:  At least 2 agreeing SignedAttestation objects
        """
        if len(attestations) < 2:
            raise EscrowClientError(
                f"Need at least 2 attestations, got {len(attestations)}"
            )

        # Serialise to the JSON format expected by the CLI resolve-oracle command
        attestations_json = json.dumps([
            {
                "pubkey": a.pubkey,
                "signature": a.signature,
                "content": a.content,
            }
            for a in attestations
        ])

        await self._run(
            "module", "escrow", "resolve-oracle",
            escrow_id,
            attestations_json,
        )

    async def claim_timeout(self, escrow_id: str) -> None:
        """
        Claim escrow funds after the timelock has expired.

        The caller's key must match the authorized party for the configured
        timeout_action (buyer for "refund", seller for "release").
        """
        await self._run("module", "escrow", "claim-timeout", escrow_id)

    async def get_public_key(self) -> str:
        """Return the client's secp256k1 public key (hex)."""
        data = await self._run("module", "escrow", "public-key")
        return data["public_key"]
