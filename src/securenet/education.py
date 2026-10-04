"""Small bounded demonstrations for classical and public-key cryptography."""

from __future__ import annotations

import base64
import os
import string

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding

ALPHABET = string.ascii_uppercase


def _letters(value: str) -> str:
    return value.upper().replace(" ", "")


def caesar(text: str, shift: int, decrypt: bool = False) -> str:
    shift = (-shift if decrypt else shift) % 26
    return "".join(ALPHABET[(ALPHABET.index(c) + shift) % 26] if c in ALPHABET else c for c in text.upper())


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    key = _letters(key)
    if not key or any(c not in ALPHABET for c in key):
        raise ValueError("Vigenère key must contain letters")
    output, position = [], 0
    for character in text.upper():
        if character in ALPHABET:
            shift = ALPHABET.index(key[position % len(key)])
            output.append(ALPHABET[(ALPHABET.index(character) + (-shift if decrypt else shift)) % 26])
            position += 1
        else:
            output.append(character)
    return "".join(output)


def xor_bytes(text: str, key: str) -> dict:
    if not key:
        raise ValueError("XOR key cannot be empty")
    data, key_bytes = text.encode(), key.encode()
    result = bytes(value ^ key_bytes[index % len(key_bytes)] for index, value in enumerate(data))
    return {"ciphertext": base64.b64encode(result).decode(), "decoded": bytes(value ^ key_bytes[index % len(key_bytes)] for index, value in enumerate(result)).decode(errors="replace"), "input_bytes": len(data)}


def rsa_demo(text: str) -> dict:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encrypted = private.public_key().encrypt(text.encode(), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    clear = private.decrypt(encrypted, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return {"ciphertext": base64.b64encode(encrypted).decode(), "decrypted": clear.decode(), "public_key": public, "private_key_hidden": True}


def signature_demo(text: str) -> dict:
    private = ed25519.Ed25519PrivateKey.generate()
    signature = private.sign(text.encode())
    public = private.public_key()
    public.verify(signature, text.encode())
    return {"signature": base64.b64encode(signature).decode(), "verified": True, "public_key": base64.b64encode(public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(), "private_key_hidden": True}


def overview() -> dict:
    return {"techniques": [
        {"name": "Caesar cipher", "type": "classical", "purpose": "Educational letter shifting; not secure."},
        {"name": "Vigenère cipher", "type": "classical", "purpose": "Educational repeating-key substitution; not secure."},
        {"name": "XOR", "type": "classical", "purpose": "Educational bit operation; a repeating key is not secure encryption."},
        {"name": "RSA", "type": "public-key encryption", "purpose": "Educational public-key encryption with OAEP."},
        {"name": "ECC / X25519", "type": "key exchange", "purpose": "Derive shared session material; does not itself encrypt files."},
        {"name": "Ed25519", "type": "digital signature", "purpose": "Prove that a public-key identity signed data."},
    ]}
