"""
Unit tests for EscrowClient.

These tests mock subprocess calls — no running federation required.
Run with: pytest backend/fedimint/test_escrow_client.py -v
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.fedimint.escrow_client import (
    EscrowClient,
    EscrowClientError,
    EscrowNotFoundError,
    EscrowStateError,
    SignedAttestation,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SELLER_PUBKEY = "02" + "ab" * 32
ORACLE_PUBKEYS = [
    "02" + "aa" * 32,
    "02" + "bb" * 32,
    "02" + "cc" * 32,
]
ESCROW_ID = "testEscrowId0001"
SECRET_CODE = "sUpErSeCrEtCoDeXyZ123"

CREATE_RESPONSE = {
    "escrow-id": ESCROW_ID,
    "secret-code": SECRET_CODE,
    "state": "escrow opened!",
}

INFO_RESPONSE = {
    "buyer_pubkey": "02" + "11" * 32,
    "seller_pubkey": SELLER_PUBKEY,
    "oracle_pubkeys": ORACLE_PUBKEYS,
    "amount": {"msats": 100_000_000},
    "state": "Open",
    "timeout_block": 900_000,
    "timeout_action": "Refund",
}


def make_proc(stdout: dict | str, returncode: int = 0, stderr: str = ""):
    """Create a mock asyncio subprocess."""
    proc = MagicMock()
    proc.returncode = returncode
    stdout_bytes = (json.dumps(stdout) if isinstance(stdout, dict) else stdout).encode()
    proc.communicate = AsyncMock(return_value=(stdout_bytes, stderr.encode()))
    return proc


# ---------------------------------------------------------------------------
# create_escrow
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_escrow_returns_id_and_secret():
    client = EscrowClient(cli_path="fedimint-cli")
    proc = make_proc(CREATE_RESPONSE)

    with patch("asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
        result = await client.create_escrow(
            seller_pubkey=SELLER_PUBKEY,
            oracle_pubkeys=ORACLE_PUBKEYS,
            amount_sats=100_000,
            timeout_block=900_000,
            timeout_action="refund",
        )

    assert result.escrow_id == ESCROW_ID
    assert result.secret_code == SECRET_CODE

    # Verify the CLI was called with positional args in correct order
    args = mock_exec.call_args[0]
    assert "create" in args
    assert SELLER_PUBKEY in args
    assert ORACLE_PUBKEYS[0] in args
    assert ORACLE_PUBKEYS[1] in args
    assert ORACLE_PUBKEYS[2] in args
    assert "900000" in args
    assert "refund" in args


@pytest.mark.asyncio
async def test_create_escrow_wrong_oracle_count():
    client = EscrowClient(cli_path="fedimint-cli")
    with pytest.raises(EscrowClientError, match="exactly 3"):
        await client.create_escrow(
            seller_pubkey=SELLER_PUBKEY,
            oracle_pubkeys=ORACLE_PUBKEYS[:2],  # only 2
            amount_sats=100_000,
            timeout_block=900_000,
        )


@pytest.mark.asyncio
async def test_create_escrow_cli_failure_raises():
    client = EscrowClient(cli_path="fedimint-cli")
    proc = make_proc("", returncode=1, stderr="some federation error")

    with patch("asyncio.create_subprocess_exec", return_value=proc):
        with pytest.raises(EscrowClientError, match="failed"):
            await client.create_escrow(
                seller_pubkey=SELLER_PUBKEY,
                oracle_pubkeys=ORACLE_PUBKEYS,
                amount_sats=100_000,
                timeout_block=900_000,
            )


# ---------------------------------------------------------------------------
# get_escrow_info
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_escrow_info():
    client = EscrowClient(cli_path="fedimint-cli")
    proc = make_proc(INFO_RESPONSE)

    with patch("asyncio.create_subprocess_exec", return_value=proc):
        info = await client.get_escrow_info(ESCROW_ID)

    assert info.escrow_id == ESCROW_ID
    assert info.state == "Open"
    assert info.timeout_block == 900_000
    assert info.oracle_pubkeys == ORACLE_PUBKEYS


@pytest.mark.asyncio
async def test_get_escrow_info_not_found():
    client = EscrowClient(cli_path="fedimint-cli")
    proc = make_proc("", returncode=1, stderr="EscrowNotFound")

    with patch("asyncio.create_subprocess_exec", return_value=proc):
        with pytest.raises(EscrowNotFoundError):
            await client.get_escrow_info("nonexistent-id")


# ---------------------------------------------------------------------------
# claim_escrow
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_claim_escrow_success():
    client = EscrowClient(cli_path="fedimint-cli")
    proc = make_proc({"escrow_id": ESCROW_ID, "status": "resolved"})

    with patch("asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
        await client.claim_escrow(ESCROW_ID, SECRET_CODE)

    args = mock_exec.call_args[0]
    assert "claim" in args
    assert ESCROW_ID in args
    assert SECRET_CODE in args


@pytest.mark.asyncio
async def test_claim_escrow_disputed_raises():
    client = EscrowClient(cli_path="fedimint-cli")
    proc = make_proc("", returncode=1, stderr="EscrowDisputed")

    with patch("asyncio.create_subprocess_exec", return_value=proc):
        with pytest.raises(EscrowStateError, match="disputed"):
            await client.claim_escrow(ESCROW_ID, SECRET_CODE)


# ---------------------------------------------------------------------------
# initiate_dispute
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_initiate_dispute():
    client = EscrowClient(cli_path="fedimint-cli")
    proc = make_proc({"escrow_id": ESCROW_ID, "status": "disputed!"})

    with patch("asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
        await client.initiate_dispute(ESCROW_ID)

    args = mock_exec.call_args[0]
    assert "dispute" in args
    assert ESCROW_ID in args


# ---------------------------------------------------------------------------
# resolve_via_oracle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolve_via_oracle_success():
    client = EscrowClient(cli_path="fedimint-cli")
    proc = make_proc({"escrow_id": ESCROW_ID, "status": "resolved via oracle"})

    attestations = [
        SignedAttestation(
            pubkey=ORACLE_PUBKEYS[0],
            signature="aa" * 64,
            content={"escrow_id": ESCROW_ID, "outcome": "buyer", "decided_at": 1700000000},
        ),
        SignedAttestation(
            pubkey=ORACLE_PUBKEYS[1],
            signature="bb" * 64,
            content={"escrow_id": ESCROW_ID, "outcome": "buyer", "decided_at": 1700000001},
        ),
    ]

    with patch("asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
        await client.resolve_via_oracle(ESCROW_ID, attestations)

    args = mock_exec.call_args[0]
    assert "resolve-oracle" in args
    assert ESCROW_ID in args

    # Verify attestations JSON was passed and is valid
    attestations_arg = args[args.index(ESCROW_ID) + 1]
    parsed = json.loads(attestations_arg)
    assert len(parsed) == 2
    assert parsed[0]["pubkey"] == ORACLE_PUBKEYS[0]
    assert parsed[0]["content"]["outcome"] == "buyer"


@pytest.mark.asyncio
async def test_resolve_via_oracle_too_few_attestations():
    client = EscrowClient(cli_path="fedimint-cli")
    with pytest.raises(EscrowClientError, match="at least 2"):
        await client.resolve_via_oracle(
            ESCROW_ID,
            [SignedAttestation(pubkey="aa", signature="bb", content={})],
        )


# ---------------------------------------------------------------------------
# claim_timeout
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_claim_timeout():
    client = EscrowClient(cli_path="fedimint-cli")
    proc = make_proc({"escrow_id": ESCROW_ID, "status": "timeout claimed"})

    with patch("asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
        await client.claim_timeout(ESCROW_ID)

    args = mock_exec.call_args[0]
    assert "claim-timeout" in args
    assert ESCROW_ID in args


# ---------------------------------------------------------------------------
# get_public_key
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_public_key():
    client = EscrowClient(cli_path="fedimint-cli")
    proc = make_proc({"public_key": SELLER_PUBKEY})

    with patch("asyncio.create_subprocess_exec", return_value=proc):
        pubkey = await client.get_public_key()

    assert pubkey == SELLER_PUBKEY


# ---------------------------------------------------------------------------
# CLI flag passthrough
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_data_dir_and_password_passed_to_cli():
    client = EscrowClient(
        cli_path="fedimint-cli",
        data_dir="/tmp/fedimint-test",
        password="s3cr3t",
    )
    proc = make_proc({"public_key": SELLER_PUBKEY})

    with patch("asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
        await client.get_public_key()

    args = mock_exec.call_args[0]
    assert "--data-dir" in args
    assert "/tmp/fedimint-test" in args
    assert "--password" in args
    assert "s3cr3t" in args
