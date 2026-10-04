"""One-way fingerprints for the teaching UI, independent of channel encryption."""

import hashlib

MAX_TEXT_BYTES = 8 * 1024


def compare_hashes(original: str, changed: str) -> dict:
    first, second = original.encode("utf-8"), changed.encode("utf-8")
    if max(len(first), len(second)) > MAX_TEXT_BYTES:
        raise ValueError("Each text must be at most 8 KiB in UTF-8")
    rows = []
    for name, factory in (("MD5", hashlib.md5), ("SHA-256", hashlib.sha256)):
        # MD5 is explicitly a historical teaching example, never a security check.
        a = factory(first, usedforsecurity=False).digest()
        b = factory(second, usedforsecurity=False).digest()
        rows.append({
            "algorithm": name, "bits": len(a) * 8, "hex_characters": len(a) * 2,
            "original": a.hex(), "changed": b.hex(),
            "changed_bits": sum((x ^ y).bit_count() for x, y in zip(a, b)),
            "matching": a == b,
        })
    return {"original_bytes": len(first), "changed_bytes": len(second),
            "original_hex": first[:64].hex(), "changed_hex": second[:64].hex(),
            "identical_input": first == second, "rows": rows}
