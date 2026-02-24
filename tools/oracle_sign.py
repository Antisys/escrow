#!/usr/bin/env python3
"""
oracle_sign.py — Sign a Fedimint escrow oracle attestation.

Usage:
    python oracle_sign.py --privkey <hex> --escrow-id <str> \
        --outcome <buyer|seller> [--decided-at <unix_ts>] [--reason <str>]

Outputs JSON with: pubkey, signature, escrow_id, outcome, decided_at

The signing format mirrors Nostr event signing (BIP-340 Schnorr over SHA-256):
    SHA256("[0,\"<pubkey_hex>\",<decided_at>,30001,[[\"d\",\"<escrow_id>\"]],\"<outcome>\"]")

This matches attestation_signing_bytes() in fedimint-escrow-common/src/oracle.rs.
"""

import argparse
import hashlib
import json
import sys
import time

try:
    from secp256k1 import PrivateKey
except ImportError:
    print("ERROR: secp256k1 Python library not found.", file=sys.stderr)
    print("Install with: pip install secp256k1", file=sys.stderr)
    sys.exit(1)


ORACLE_ATTESTATION_KIND = 30_001


def attestation_signing_bytes(pubkey_hex: str, escrow_id: str, outcome: str, decided_at: int) -> bytes:
    """
    Compute the 32-byte message to sign, matching the Rust implementation.

    Format: SHA256 of compact JSON array:
    [0, "<pubkey_hex>", <decided_at>, 30001, [["d","<escrow_id>"]], "<outcome>"]
    """
    msg = f'[0,"{pubkey_hex}",{decided_at},{ORACLE_ATTESTATION_KIND},[["d","{escrow_id}"]],"{outcome}"]'
    return hashlib.sha256(msg.encode()).digest()


def sign_attestation(privkey_hex: str, escrow_id: str, outcome: str, decided_at: int) -> dict:
    """
    Sign an oracle attestation and return the full attestation as a dict.

    The "pubkey" field uses the full 33-byte compressed form (66 hex chars) so that
    fedimint-cli can parse it as a secp256k1::PublicKey and match against the oracle
    pubkeys registered in the escrow output.

    The signing message (inside attestation_signing_bytes) uses the x-only (32-byte)
    form, which is the BIP-340 / Nostr convention and matches the Rust implementation.
    """
    privkey_bytes = bytes.fromhex(privkey_hex)
    privkey = PrivateKey(privkey_bytes)

    # Full compressed pubkey (33 bytes = 66 hex chars) — what fedimint-cli parses
    pubkey_full_hex = privkey.pubkey.serialize(compressed=True).hex()
    # x-only pubkey (32 bytes = 64 hex chars) — used ONLY inside the signing message
    pubkey_xonly_hex = pubkey_full_hex[2:]  # drop 02/03 prefix

    msg_bytes = attestation_signing_bytes(pubkey_xonly_hex, escrow_id, outcome, decided_at)

    # BIP-340 Schnorr signature (64 bytes) — schnorr_sign returns bytes directly
    sig = privkey.schnorr_sign(msg_bytes, None, raw=True)
    sig_hex = sig.hex()

    return {
        "pubkey": pubkey_full_hex,
        "signature": sig_hex,
        "content": {
            "escrow_id": escrow_id,
            "outcome": outcome,
            "decided_at": decided_at,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Sign a Fedimint escrow oracle attestation")
    parser.add_argument("--privkey", required=True, help="Oracle private key (hex, 32 bytes)")
    parser.add_argument("--escrow-id", required=True, help="Escrow ID to attest")
    parser.add_argument(
        "--outcome",
        required=True,
        choices=["buyer", "seller"],
        help="Who receives the funds",
    )
    parser.add_argument(
        "--decided-at",
        type=int,
        default=None,
        help="Unix timestamp of decision (default: now)",
    )
    parser.add_argument("--reason", default=None, help="Human-readable reason (informational)")
    args = parser.parse_args()

    decided_at = args.decided_at if args.decided_at is not None else int(time.time())

    attestation = sign_attestation(
        privkey_hex=args.privkey,
        escrow_id=args.escrow_id,
        outcome=args.outcome,
        decided_at=decided_at,
    )

    if args.reason:
        attestation["content"]["reason"] = args.reason

    print(json.dumps(attestation, indent=2))


if __name__ == "__main__":
    main()
