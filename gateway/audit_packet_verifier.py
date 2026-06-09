"""Offline verifier for Gate Audit Packets.

Verifies an exported audit-packet JSON file without any network access
to the Gate operator.  The only optional network call is to a public
Base L2 RPC endpoint for on-chain anchor verification.

Usage:
    python -m gateway.audit_packet_verifier audit-packet.json
    python -m gateway.audit_packet_verifier audit-packet.json --verify-onchain

Verification steps (per docs/audit-packet-spec.md):
  1. Verify receipt signatures (Ed25519 over JCS-canonical body)
  2. Verify hash chain continuity (prev_receipt linkage)
  3. Verify Merkle inclusion proofs
  4. Verify on-chain anchors (optional, requires Base RPC)
  5. Cross-check metadata counts
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Cryptographic primitives (standalone — no gateway imports required)
# ---------------------------------------------------------------------------

def _base64url_decode(s: str) -> bytes:
    """Decode a base64url string with auto-padding."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


# --- JCS canonicalizer (RFC 8785 subset, inlined for standalone use) ---

def _to_utf16_units(s: str) -> list[int]:
    units: list[int] = []
    for ch in s:
        cp = ord(ch)
        if cp <= 0xFFFF:
            units.append(cp)
        else:
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
    return units


def _compare_keys_jcs(a: str, b: str) -> int:
    a_units = _to_utf16_units(a)
    b_units = _to_utf16_units(b)
    for au, bu in zip(a_units, b_units):
        if au < bu:
            return -1
        if au > bu:
            return 1
    if len(a_units) < len(b_units):
        return -1
    if len(a_units) > len(b_units):
        return 1
    return 0


import functools
import math


def _serialize_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif cp < 0x20:
            out.append(f'\\u{cp:04x}')
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _serialize(obj: object) -> str:
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int) and not isinstance(obj, bool):
        return str(obj)
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError("NaN/Infinity not allowed")
        raise ValueError("Floats forbidden in v0.1")
    if isinstance(obj, str):
        return _serialize_string(obj)
    if isinstance(obj, list):
        return "[" + ",".join(_serialize(item) for item in obj) + "]"
    if isinstance(obj, dict):
        sorted_keys = sorted(obj.keys(), key=functools.cmp_to_key(_compare_keys_jcs))
        pairs = [_serialize_string(k) + ":" + _serialize(obj[k]) for k in sorted_keys]
        return "{" + ",".join(pairs) + "}"
    raise ValueError(f"Unsupported type: {type(obj)}")


def canonicalize(obj: object) -> bytes:
    return _serialize(obj).encode("utf-8")


# --- Merkle tree (inlined from gateway/merkle.py for standalone use) ---

UNIFIED_LEAF_DOMAIN = b"BI_ARTIFACT_LEAF_V1"
UNIFIED_NODE_DOMAIN = b"BI_ARTIFACT_NODE_V1"


def unified_leaf_hash(artifact_hash_hex: str) -> bytes:
    return hashlib.sha256(UNIFIED_LEAF_DOMAIN + b"\x00" + bytes.fromhex(artifact_hash_hex)).digest()


def unified_node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(UNIFIED_NODE_DOMAIN + b"\x00" + left + right).digest()


# ---------------------------------------------------------------------------
# Verification steps
# ---------------------------------------------------------------------------

GENESIS_PREV_RECEIPT = "sha256:" + "0" * 64


class VerificationReport:
    """Accumulates verification results across all steps."""

    def __init__(self):
        self.receipt_sig_ok = 0
        self.receipt_sig_fail = 0
        self.receipt_hash_ok = 0
        self.receipt_hash_fail = 0
        self.chain_links_ok = 0
        self.chain_links_fail = 0
        self.chain_links_skip = 0
        self.inclusion_ok = 0
        self.inclusion_fail = 0
        self.anchor_ok = 0
        self.anchor_fail = 0
        self.anchor_skip = 0
        self.metadata_ok = True
        self.errors: list[str] = []

    def error(self, msg: str):
        self.errors.append(msg)

    def summary(self) -> str:
        lines = [
            "",
            "=== Gate Audit Packet Verification Report ===",
            "",
            f"Receipt signatures : {self.receipt_sig_ok} verified, {self.receipt_sig_fail} FAILED",
            f"Receipt hashes     : {self.receipt_hash_ok} verified, {self.receipt_hash_fail} FAILED",
            f"Chain links        : {self.chain_links_ok} valid, {self.chain_links_fail} BROKEN, {self.chain_links_skip} skipped",
            f"Inclusion proofs   : {self.inclusion_ok} verified, {self.inclusion_fail} FAILED",
            f"On-chain anchors   : {self.anchor_ok} confirmed, {self.anchor_fail} FAILED, {self.anchor_skip} skipped",
            f"Metadata cross-check: {'PASS' if self.metadata_ok else 'FAIL'}",
            "",
        ]
        if self.errors:
            lines.append(f"Errors ({len(self.errors)}):")
            for e in self.errors:
                lines.append(f"  - {e}")
            lines.append("")

        total_failures = (
            self.receipt_sig_fail + self.receipt_hash_fail +
            self.chain_links_fail + self.inclusion_fail +
            self.anchor_fail + (0 if self.metadata_ok else 1)
        )
        if total_failures == 0:
            lines.append("VERDICT: PASS - All verifications succeeded.")
        else:
            lines.append(f"VERDICT: FAIL - {total_failures} failure(s) detected.")

        return "\n".join(lines)

    @property
    def passed(self) -> bool:
        return (
            self.receipt_sig_fail == 0
            and self.receipt_hash_fail == 0
            and self.chain_links_fail == 0
            and self.inclusion_fail == 0
            and self.anchor_fail == 0
            and self.metadata_ok
        )


def _load_ed25519_public_key(jwk: dict):
    """Load an Ed25519 public key from a JWK dict."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    x_bytes = _base64url_decode(jwk["x"])
    return Ed25519PublicKey.from_public_bytes(x_bytes)


def _resolve_key(kid: str, public_keys: dict) -> dict | None:
    """Find a JWK in the public_keys map by kid."""
    for _label, jwk in public_keys.items():
        if jwk.get("kid") == kid:
            return jwk
    return None


# Step 1: Verify receipt signatures
def verify_receipt_signatures(packet: dict, report: VerificationReport) -> None:
    from cryptography.exceptions import InvalidSignature

    public_keys = packet.get("public_keys", {})
    for receipt in packet.get("receipts", []):
        body = receipt.get("body", {})
        sig = receipt.get("sig", {})
        claimed_hash = receipt.get("receipt_hash", "")

        # 1a. Canonicalize body and check hash
        try:
            body_bytes = canonicalize(body)
        except Exception as e:
            report.receipt_hash_fail += 1
            report.error(f"Seq {body.get('seq')}: canonicalization failed: {e}")
            continue

        computed_hash = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
        if computed_hash == claimed_hash:
            report.receipt_hash_ok += 1
        else:
            report.receipt_hash_fail += 1
            report.error(
                f"Seq {body.get('seq')}: hash mismatch "
                f"(computed={computed_hash[:32]}..., claimed={claimed_hash[:32]}...)"
            )

        # 1b. Verify Ed25519 signature
        kid = sig.get("kid", "")
        jwk = _resolve_key(kid, public_keys)
        if not jwk:
            report.receipt_sig_fail += 1
            report.error(f"Seq {body.get('seq')}: no public key found for kid={kid}")
            continue

        try:
            pub_key = _load_ed25519_public_key(jwk)
            sig_bytes = _base64url_decode(sig.get("value", ""))
            pub_key.verify(sig_bytes, body_bytes)
            report.receipt_sig_ok += 1
        except InvalidSignature:
            report.receipt_sig_fail += 1
            report.error(f"Seq {body.get('seq')}: INVALID Ed25519 signature")
        except Exception as e:
            report.receipt_sig_fail += 1
            report.error(f"Seq {body.get('seq')}: signature error: {e}")


# Step 2: Verify hash chain continuity
def verify_chain_continuity(packet: dict, report: VerificationReport) -> None:
    receipts = packet.get("receipts", [])
    if not receipts:
        return

    # Sort by seq (numeric)
    sorted_receipts = sorted(
        receipts,
        key=lambda r: int(r.get("body", {}).get("seq", "0") or "0"),
    )

    # Check first receipt
    first_prev = sorted_receipts[0].get("body", {}).get("prev_receipt", "")
    if first_prev == GENESIS_PREV_RECEIPT:
        report.chain_links_ok += 1
    else:
        # Might be a partial export starting mid-chain
        report.chain_links_skip += 1

    # Check subsequent links
    for i in range(1, len(sorted_receipts)):
        prev_hash = sorted_receipts[i - 1].get("receipt_hash", "")
        curr_prev = sorted_receipts[i].get("body", {}).get("prev_receipt", "")
        curr_seq = sorted_receipts[i].get("body", {}).get("seq", "?")

        if not prev_hash or not curr_prev:
            report.chain_links_skip += 1
            continue

        if curr_prev == prev_hash:
            report.chain_links_ok += 1
        else:
            report.chain_links_fail += 1
            report.error(
                f"Seq {curr_seq}: chain break "
                f"(prev_receipt={curr_prev[:32]}..., expected={prev_hash[:32]}...)"
            )


# Step 3: Verify Merkle inclusion proofs
def verify_inclusion_proofs(packet: dict, report: VerificationReport) -> None:
    inclusion_proofs = packet.get("inclusion_proofs", {})

    for receipt_hash, proof_data in inclusion_proofs.items():
        target_hex = receipt_hash.removeprefix("sha256:")
        merkle_root = proof_data.get("merkle_root", "")
        proof_path = proof_data.get("proof", [])

        # Start from the leaf
        current = unified_leaf_hash(target_hex)

        for step in proof_path:
            sibling = bytes.fromhex(step["hash"])
            if step["direction"] == "right":
                current = unified_node_hash(current, sibling)
            else:
                current = unified_node_hash(sibling, current)

        computed_root = "sha256:" + current.hex()
        if computed_root == merkle_root:
            report.inclusion_ok += 1
        else:
            report.inclusion_fail += 1
            report.error(
                f"Inclusion proof for {receipt_hash[:32]}...: "
                f"computed root={computed_root[:32]}..., expected={merkle_root[:32]}..."
            )


# Step 4: Verify on-chain anchors (optional)
def verify_onchain_anchors(packet: dict, report: VerificationReport, rpc_url: str | None = None) -> None:
    anchor_proofs = packet.get("anchor_proofs", [])

    if not rpc_url:
        report.anchor_skip += len(anchor_proofs)
        return

    import urllib.request

    for anchor in anchor_proofs:
        tx_hash = anchor.get("tx_hash", "")
        expected_root = anchor.get("merkle_root", "")

        if not tx_hash:
            report.anchor_skip += 1
            continue

        try:
            payload = json.dumps({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionByHash",
                "params": [tx_hash],
                "id": 1,
            }).encode()

            req = urllib.request.Request(
                rpc_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            tx = data.get("result")
            if not tx:
                report.anchor_fail += 1
                report.error(f"Anchor {tx_hash}: transaction not found on-chain")
                continue

            # The merkle root is in calldata (input field)
            calldata = tx.get("input", "")
            root_hex = expected_root.removeprefix("sha256:")

            if root_hex in calldata:
                report.anchor_ok += 1
            else:
                report.anchor_fail += 1
                report.error(
                    f"Anchor {tx_hash}: calldata does not contain expected root {root_hex[:24]}..."
                )

        except Exception as e:
            report.anchor_fail += 1
            report.error(f"Anchor {tx_hash}: RPC error: {e}")


# Step 5: Cross-check metadata
def verify_metadata(packet: dict, report: VerificationReport) -> None:
    meta = packet.get("metadata", {})
    receipts = packet.get("receipts", [])
    anchors = packet.get("anchor_proofs", [])

    expected_count = len(receipts)
    if meta.get("receipt_count") != expected_count:
        report.metadata_ok = False
        report.error(
            f"Metadata receipt_count={meta.get('receipt_count')} "
            f"but packet has {expected_count} receipts"
        )

    approval_count = sum(
        1 for r in receipts
        if r.get("body", {}).get("decision") == "approve"
    )
    denial_count = sum(
        1 for r in receipts
        if r.get("body", {}).get("decision") == "deny"
    )

    if meta.get("approval_count") != approval_count:
        report.metadata_ok = False
        report.error(
            f"Metadata approval_count={meta.get('approval_count')}, actual={approval_count}"
        )
    if meta.get("denial_count") != denial_count:
        report.metadata_ok = False
        report.error(
            f"Metadata denial_count={meta.get('denial_count')}, actual={denial_count}"
        )
    if meta.get("anchor_count") != len(anchors):
        report.metadata_ok = False
        report.error(
            f"Metadata anchor_count={meta.get('anchor_count')}, actual={len(anchors)}"
        )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

BASE_MAINNET_RPC = "https://mainnet.base.org"


def verify_audit_packet(
    packet: dict,
    verify_onchain: bool = False,
    rpc_url: str | None = None,
) -> VerificationReport:
    """Run all verification steps on an audit packet and return the report."""
    report = VerificationReport()

    print(f"Verifying audit packet v{packet.get('version', '?')}")
    print(f"  Tenant: {packet.get('tenant')}")
    print(f"  Generated: {packet.get('generated_at')}")
    print(f"  Receipts: {len(packet.get('receipts', []))}")
    print(f"  Anchors: {len(packet.get('anchor_proofs', []))}")
    print(f"  Inclusion proofs: {len(packet.get('inclusion_proofs', {}))}")
    print()

    print("Step 1: Verifying receipt signatures and hashes...")
    verify_receipt_signatures(packet, report)

    print("Step 2: Verifying hash chain continuity...")
    verify_chain_continuity(packet, report)

    print("Step 3: Verifying Merkle inclusion proofs...")
    verify_inclusion_proofs(packet, report)

    if verify_onchain:
        print("Step 4: Verifying on-chain anchors (Base L2)...")
        verify_onchain_anchors(packet, report, rpc_url=rpc_url or BASE_MAINNET_RPC)
    else:
        print("Step 4: Skipping on-chain verification (use --verify-onchain to enable)")
        report.anchor_skip += len(packet.get("anchor_proofs", []))

    print("Step 5: Cross-checking metadata...")
    verify_metadata(packet, report)

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Verify a Gate Audit Packet offline",
        prog="python -m gateway.audit_packet_verifier",
    )
    parser.add_argument("packet_file", help="Path to the audit packet JSON file")
    parser.add_argument(
        "--verify-onchain",
        action="store_true",
        help="Verify on-chain anchors via Base L2 RPC (requires network)",
    )
    parser.add_argument(
        "--rpc-url",
        default=BASE_MAINNET_RPC,
        help=f"Base L2 RPC URL (default: {BASE_MAINNET_RPC})",
    )
    args = parser.parse_args()

    path = Path(args.packet_file)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        packet = json.load(f)

    report = verify_audit_packet(
        packet,
        verify_onchain=args.verify_onchain,
        rpc_url=args.rpc_url,
    )
    print(report.summary())
    sys.exit(0 if report.passed else 1)


if __name__ == "__main__":
    main()
