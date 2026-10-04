"""Vetted primitives, persistent identities, and directional record protection."""

from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALGORITHMS = ("AES-256-GCM", "ChaCha20-Poly1305")
HEADER = struct.Struct("!BQI")
MAX_RECORD = 128 * 1024
MAX_RECORDS = 1_000_000
JSON_RECORD, FILE_CHUNK = 1, 2


class ProtocolError(Exception):
    """A public, deliberately non-sensitive protocol failure code."""


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def public_bytes(key) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()


def write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(data)


def initialize_identities(directory: Path, password_file: Path) -> None:
    """Local trust provisioning; never learns a peer key from the network."""
    if not password_file.exists():
        write_private(password_file, os.urandom(32).hex().encode())
    password = password_file.read_bytes().strip()
    if len(password) < 16:
        raise ValueError("Identity password must contain at least 16 bytes")
    keys = {}
    for role in ("sender", "receiver"):
        path = directory / role / "identity.pem"
        if not path.exists():
            key = Ed25519PrivateKey.generate()
            write_private(path, key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(password),
            ))
        keys[role] = load_identity(path, password_file)
    for role, peer in (("sender", "receiver"), ("receiver", "sender")):
        path = directory / role / "peer.pub"
        expected = public_bytes(keys[peer].public_key())
        if path.exists():
            if path.read_bytes() != expected:
                raise ValueError("Pinned peer identity mismatch; explicit rotation required")
        else:
            write_private(path, expected)


def load_identity(path: Path, password_file: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password_file.read_bytes().strip())
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected Ed25519 identity")
    return key


@dataclass
class RecordCipher:
    key: bytes
    prefix: bytes
    context: bytes
    algorithm: str
    sequence: int = 0

    def __post_init__(self):
        if self.algorithm not in ALGORITHMS or len(self.key) != 32 or len(self.prefix) != 4:
            raise ValueError("Invalid cipher parameters")
        self.aead = AESGCM(self.key) if self.algorithm == ALGORITHMS[0] else ChaCha20Poly1305(self.key)

    def seal(self, payload: bytes, kind: int = JSON_RECORD) -> bytes:
        if kind not in (JSON_RECORD, FILE_CHUNK) or len(payload) + HEADER.size + 16 > MAX_RECORD:
            raise ProtocolError("RECORD_TOO_LARGE_OR_INVALID")
        if self.sequence >= MAX_RECORDS:
            raise ProtocolError("REKEY_REQUIRED")
        header = HEADER.pack(kind, self.sequence, len(payload) + 16)
        nonce = self.prefix + self.sequence.to_bytes(8, "big")
        ciphertext = self.aead.encrypt(nonce, payload, self.context + header)
        self.sequence += 1
        return header + ciphertext

    def open(self, record: bytes) -> tuple[int, bytes]:
        if len(record) < HEADER.size + 16 or len(record) > MAX_RECORD:
            raise ProtocolError("INVALID_RECORD")
        kind, seq, length = HEADER.unpack(record[:HEADER.size])
        if kind not in (JSON_RECORD, FILE_CHUNK) or length != len(record) - HEADER.size:
            raise ProtocolError("INVALID_RECORD")
        if seq != self.sequence:
            raise ProtocolError("REPLAY_OR_SEQUENCE_REJECTED")
        if self.sequence >= MAX_RECORDS:
            raise ProtocolError("REKEY_REQUIRED")
        nonce = self.prefix + seq.to_bytes(8, "big")
        try:
            payload = self.aead.decrypt(nonce, record[HEADER.size:], self.context + record[:HEADER.size])
        except InvalidTag as exc:
            raise ProtocolError("AUTHENTICATION_FAILED") from exc
        self.sequence += 1
        return kind, payload

    def inspect(self, record: bytes) -> dict:
        """A bounded view of real wire bytes, deliberately excluding secret keys."""
        kind, seq, _ = HEADER.unpack(record[:HEADER.size])
        ciphertext = record[HEADER.size:-16]
        return {
            "sequence": seq, "kind": kind,
            "nonce": (self.prefix + seq.to_bytes(8, "big")).hex(),
            "header": record[:HEADER.size].hex(),
            "ciphertext": ciphertext[:512].hex(),
            "ciphertext_bytes": len(ciphertext), "truncated": len(ciphertext) > 512,
            "tag": record[-16:].hex(), "wire_bytes": len(record) + 4,
        }


def derive_ciphers(secret: bytes, transcript: bytes, algorithm: str, sender: bool):
    digest = hashlib.sha256(transcript).digest()
    material = HKDF(algorithm=hashes.SHA256(), length=72, salt=digest,
                    info=b"securenet/v1/directional-record-keys").derive(secret)
    outbound = RecordCipher(material[:32], material[64:68], digest + b"s2r", algorithm)
    inbound = RecordCipher(material[32:64], material[68:72], digest + b"r2s", algorithm)
    return (outbound, inbound) if sender else (inbound, outbound)
