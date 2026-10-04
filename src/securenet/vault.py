"""Envelope-encrypted private file storage with streaming AES-GCM."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"SNL-FILE-1\0"
CHUNK = 64 * 1024


def sha256_file(path: Path) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as source:
        while chunk := source.read(CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def encrypt_file(source: Path, destination: Path, key: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(MAGIC)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as target, source.open("rb") as input_file:
            target.write(MAGIC + nonce)
            while chunk := input_file.read(CHUNK):
                target.write(encryptor.update(chunk))
            target.write(encryptor.finalize())
            target.write(encryptor.tag)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def decrypt_file(source: Path, destination: Path, key: bytes) -> None:
    size = source.stat().st_size
    if size < len(MAGIC) + 12 + 16:
        raise ValueError("Encrypted file is too short")
    with source.open("rb") as encrypted:
        if encrypted.read(len(MAGIC)) != MAGIC:
            raise ValueError("Encrypted file header is invalid")
        nonce = encrypted.read(12)
        encrypted_size = size - len(MAGIC) - 12 - 16
        encrypted.seek(size - 16)
        tag = encrypted.read(16)
        encrypted.seek(len(MAGIC) + 12)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(MAGIC)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as clear:
                remaining = encrypted_size
                while remaining:
                    chunk = encrypted.read(min(CHUNK, remaining))
                    if not chunk:
                        raise ValueError("Encrypted file ended unexpectedly")
                    remaining -= len(chunk)
                    clear.write(decryptor.update(chunk))
                clear.write(decryptor.finalize())
        except (InvalidTag, BaseException):
            destination.unlink(missing_ok=True)
            raise


def compare_bytes(first: Path, second: Path) -> dict:
    matched, different, total = 0, 0, 0
    with first.open("rb") as a, second.open("rb") as b:
        while True:
            left, right = a.read(CHUNK), b.read(CHUNK)
            if not left and not right:
                break
            width = max(len(left), len(right))
            for index in range(width):
                total += 1
                if index < len(left) and index < len(right) and left[index] == right[index]:
                    matched += 1
                else:
                    different += 1
    return {"total_bytes": total, "matched_bytes": matched, "different_bytes": different,
            "identical": different == 0 and first.stat().st_size == second.stat().st_size}
