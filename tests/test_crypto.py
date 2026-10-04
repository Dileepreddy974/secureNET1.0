import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from securenet.crypto import (ALGORITHMS, FILE_CHUNK, HEADER, MAX_RECORD, MAX_RECORDS,
                             ProtocolError, RecordCipher, derive_ciphers,
                             initialize_identities, load_identity, public_bytes, write_private)


def pair(algorithm):
    key, prefix = os.urandom(32), os.urandom(4)
    return (RecordCipher(key, prefix, b"test/session/s2r", algorithm),
            RecordCipher(key, prefix, b"test/session/s2r", algorithm))


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("payload", [b"", b"hello", "హలో 🔒".encode(), os.urandom(65536)])
def test_round_trip(algorithm, payload):
    tx, rx = pair(algorithm)
    sealed = tx.seal(payload, FILE_CHUNK)
    kind, decrypted = rx.open(sealed)
    assert decrypted == payload and kind == FILE_CHUNK
    assert rx.sequence == tx.sequence == 1
    if payload:
        assert payload not in sealed


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("part", ["ciphertext", "tag", "kind", "context", "key", "nonce"])
def test_authentication_failures_never_advance_receive_counter(algorithm, part):
    tx, rx = pair(algorithm)
    sealed = bytearray(tx.seal(b"private payload"))
    if part == "ciphertext":
        sealed[HEADER.size] ^= 1
    elif part == "tag":
        sealed[-1] ^= 1
    elif part == "kind":
        sealed[0] = FILE_CHUNK
    elif part == "context":
        rx.context = b"another-session"
    elif part == "nonce":
        rx.prefix = os.urandom(4)
    else:
        rx = RecordCipher(os.urandom(32), rx.prefix, rx.context, algorithm)
    with pytest.raises(ProtocolError, match="AUTHENTICATION_FAILED"):
        rx.open(bytes(sealed))
    assert rx.sequence == 0


def test_replay_ordering_and_cross_session_rejected():
    tx, rx = pair(ALGORITHMS[0])
    first, second = tx.seal(b"one"), tx.seal(b"two")
    with pytest.raises(ProtocolError, match="SEQUENCE"):
        rx.open(second)
    assert rx.open(first)[1] == b"one"
    with pytest.raises(ProtocolError, match="SEQUENCE"):
        rx.open(first)
    other_tx, _ = pair(ALGORITHMS[0])
    rx2 = RecordCipher(rx.key, rx.prefix, b"different", ALGORITHMS[0])
    with pytest.raises(ProtocolError, match="AUTHENTICATION"):
        rx2.open(first)
    assert other_tx.key != tx.key


def test_nonce_uniqueness_direction_separation_and_session_rotation():
    transcript, secret = b"signed handshake", os.urandom(32)
    tx, rx = derive_ciphers(secret, transcript, ALGORITHMS[0], True)
    receiver_tx, receiver_rx = derive_ciphers(secret, transcript, ALGORITHMS[0], False)
    assert tx.key == receiver_rx.key and rx.key == receiver_tx.key and tx.key != rx.key
    nonces = {tx.inspect(tx.seal(b"same data"))["nonce"] for _ in range(1000)}
    assert len(nonces) == 1000
    fresh, _ = derive_ciphers(os.urandom(32), transcript, ALGORITHMS[0], True)
    assert fresh.key != tx.key
    view = tx.inspect(tx.seal(b"a" * 1000))
    assert view["truncated"] and len(view["ciphertext"]) == 1024
    assert "key" not in view


def test_record_bounds_and_exhaustion():
    tx, rx = pair(ALGORITHMS[0])
    for invalid in (b"", b"x" * 15, b"x" * (MAX_RECORD + 1)):
        with pytest.raises(ProtocolError, match="INVALID_RECORD"):
            rx.open(invalid)
    for payload, kind in ((b"x" * MAX_RECORD, 1), (b"ok", 9)):
        with pytest.raises(ProtocolError):
            tx.seal(payload, kind)
    valid = tx.seal(b"abc")
    for bad in (HEADER.pack(9, 0, 19) + valid[HEADER.size:], HEADER.pack(1, 0, 20) + valid[HEADER.size:]):
        with pytest.raises(ProtocolError, match="INVALID_RECORD"):
            rx.open(bad)
    tx.sequence = rx.sequence = MAX_RECORDS
    with pytest.raises(ProtocolError, match="REKEY"):
        tx.seal(b"x")
    with pytest.raises(ProtocolError, match="REKEY"):
        rx.open(HEADER.pack(1, MAX_RECORDS, 19) + valid[HEADER.size:])
    with pytest.raises(ValueError):
        RecordCipher(os.urandom(32), b"bad", b"", "unknown")


def test_identity_storage_and_pin_rotation(identities):
    keys, password = identities["keys"], identities["password"]
    original = (keys / "sender/identity.pem").read_bytes()
    assert b"ENCRYPTED PRIVATE KEY" in original
    assert stat.S_IMODE((keys / "sender/identity.pem").stat().st_mode) == 0o600
    initialize_identities(keys, password)
    assert (keys / "sender/identity.pem").read_bytes() == original
    (keys / "sender/peer.pub").write_bytes(public_bytes(Ed25519PrivateKey.generate().public_key()))
    with pytest.raises(ValueError, match="rotation"):
        initialize_identities(keys, password)


def test_private_key_validation(tmp_path):
    password = tmp_path / "password"
    password.write_bytes(b"short")
    with pytest.raises(ValueError, match="16 bytes"):
        initialize_identities(tmp_path / "keys", password)
    password.write_bytes(b"a sufficient password")
    key = generate_private_key(65537, 2048)
    path = tmp_path / "rsa.pem"
    write_private(path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.BestAvailableEncryption(password.read_bytes())))
    with pytest.raises(ValueError, match="Ed25519"):
        load_identity(path, password)
    with pytest.raises(FileExistsError):
        write_private(path, b"do not overwrite")
