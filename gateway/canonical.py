"""JCS-subset canonicalizer for receipt bodies.

Adapted from the Receipt Chain Verification Protocol v0.1 reference implementation.
See: SPEC.md in receipt-chain-verifier for the full specification.
"""

from __future__ import annotations

import functools
import json
import math


class CanonicalizationError(Exception):
    pass


def _compare_keys_jcs(a: str, b: str) -> int:
    """Compare two keys by UTF-16 code unit values, per RFC 8785 Section 3.2.3."""
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


def _to_utf16_units(s: str) -> list[int]:
    units = []
    for ch in s:
        cp = ord(ch)
        if cp <= 0xFFFF:
            units.append(cp)
        else:
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
    return units


def canonicalize(obj: object) -> bytes:
    """Canonicalize a Python object to JCS-subset bytes."""
    return _serialize(obj).encode("utf-8")


def _serialize(obj: object) -> str:
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int) and not isinstance(obj, bool):
        return str(obj)
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise CanonicalizationError("NaN and Infinity are not valid JSON values")
        raise CanonicalizationError("Floating-point values are forbidden in v0.1")
    if isinstance(obj, str):
        return _serialize_string(obj)
    if isinstance(obj, list):
        return "[" + ",".join(_serialize(item) for item in obj) + "]"
    if isinstance(obj, dict):
        sorted_keys = sorted(obj.keys(), key=functools.cmp_to_key(_compare_keys_jcs))
        pairs = [_serialize_string(k) + ":" + _serialize(obj[k]) for k in sorted_keys]
        return "{" + ",".join(pairs) + "}"
    raise CanonicalizationError(f"Unsupported type: {type(obj)}")


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
