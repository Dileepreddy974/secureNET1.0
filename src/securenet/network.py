"""Bounded TCP framing and mutually authenticated ephemeral X25519 handshake."""

from __future__ import annotations

import asyncio
import json
import os
import struct
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .crypto import (ALGORITHMS, JSON_RECORD, MAX_RECORD, ProtocolError, canonical,
                     derive_ciphers, fingerprint, public_bytes)

TIMEOUT = 20
HANDSHAKE_LIMIT = 8192


async def read_frame(reader: asyncio.StreamReader, limit: int = MAX_RECORD, idle_timeout=TIMEOUT) -> bytes:
    try:
        header = await asyncio.wait_for(reader.readexactly(4), idle_timeout)
        size = struct.unpack("!I", header)[0]
        if size == 0 or size > limit:
            raise ProtocolError("FRAME_SIZE_REJECTED")
        return await asyncio.wait_for(reader.readexactly(size), TIMEOUT)
    except asyncio.IncompleteReadError as exc:
        raise ProtocolError("CONNECTION_CLOSED") from exc
    except TimeoutError as exc:
        raise ProtocolError("CONNECTION_TIMEOUT") from exc


async def write_frame(writer: asyncio.StreamWriter, data: bytes) -> None:
    if not data or len(data) > MAX_RECORD:
        raise ProtocolError("FRAME_SIZE_REJECTED")
    writer.write(struct.pack("!I", len(data)) + data)
    try:
        await asyncio.wait_for(writer.drain(), TIMEOUT)
    except (ConnectionError, TimeoutError) as exc:
        raise ProtocolError("CONNECTION_CLOSED") from exc


def parse_object(raw: bytes) -> dict:
    try:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("INVALID_MESSAGE") from exc


@dataclass
class Channel:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    tx: object
    rx: object
    handshake: dict
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    idle_timeout: float = TIMEOUT

    async def send(self, payload: bytes, kind: int = JSON_RECORD) -> bytes:
        async with self.send_lock:
            record = self.tx.seal(payload, kind)
            await write_frame(self.writer, record)
            return record

    async def send_json(self, value: dict) -> bytes:
        return await self.send(canonical(value))

    async def receive(self) -> tuple[int, bytes]:
        return self.rx.open(await read_frame(self.reader, idle_timeout=self.idle_timeout))

    async def receive_json(self) -> dict:
        kind, raw = await self.receive()
        if kind != JSON_RECORD:
            raise ProtocolError("UNEXPECTED_RECORD_TYPE")
        return parse_object(raw)

    async def close(self):
        self.writer.close()
        try:
            await asyncio.wait_for(self.writer.wait_closed(), 2)
        except (ConnectionError, TimeoutError):
            pass


def verify_signature(public: bytes, signature: str, transcript: bytes):
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(bytes.fromhex(signature), transcript)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ProtocolError("HANDSHAKE_SIGNATURE_REJECTED") from exc


def validate_hello(hello: dict, pinned: bytes) -> None:
    try:
        if hello["version"] != 1 or hello["algorithm"] not in ALGORITHMS:
            raise ProtocolError("UNSUPPORTED_PROTOCOL")
        if bytes.fromhex(hello["identity"]) != pinned:
            raise ProtocolError("PEER_IDENTITY_REJECTED")
        if len(bytes.fromhex(hello["ephemeral"])) != 32 or len(bytes.fromhex(hello["challenge"])) != 32:
            raise ValueError()
    except (KeyError, ValueError, TypeError) as exc:
        raise ProtocolError("INVALID_HANDSHAKE") from exc


def hello_for(identity, ephemeral, algorithm, context=None):
    hello = {"version": 1, "algorithm": algorithm,
            "identity": public_bytes(identity.public_key()).hex(),
            "ephemeral": public_bytes(ephemeral.public_key()).hex(),
            "challenge": os.urandom(32).hex()}
    if context is not None:
        hello["context"] = context
    return hello


def validate_context(actual: dict | None, expected: dict | None) -> None:
    if expected is None:
        return
    if not isinstance(actual, dict) or canonical(actual) != canonical(expected):
        raise ProtocolError("TRANSFER_CONTEXT_REJECTED")


async def client_handshake(reader, writer, identity, peer: bytes, algorithm=ALGORITHMS[0],
                           context: dict | None = None, expected_peer_context: dict | None = None):
    started = time.perf_counter()
    if algorithm not in ALGORITHMS:
        raise ProtocolError("UNSUPPORTED_PROTOCOL")
    ephemeral = X25519PrivateKey.generate()
    hello = hello_for(identity, ephemeral, algorithm, context)
    await write_frame(writer, canonical(hello))
    response = parse_object(await read_frame(reader, HANDSHAKE_LIMIT))
    remote = response.get("hello", {})
    if not isinstance(remote, dict):
        raise ProtocolError("INVALID_HANDSHAKE")
    validate_hello(remote, peer)
    validate_context(remote.get("context"), expected_peer_context)
    if remote["algorithm"] != algorithm:
        raise ProtocolError("ALGORITHM_DOWNGRADE_REJECTED")
    transcript = canonical({"protocol": "securenet/v1", "sender": hello, "receiver": remote})
    verify_signature(peer, response.get("signature", ""), b"receiver:" + transcript)
    await write_frame(writer, canonical({"signature": identity.sign(b"sender:" + transcript).hex()}))
    try:
        secret = ephemeral.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(remote["ephemeral"])))
    except ValueError as exc:
        raise ProtocolError("INVALID_EPHEMERAL_KEY") from exc
    tx, rx = derive_ciphers(secret, transcript, algorithm, True)
    channel = Channel(reader, writer, tx, rx, {})
    await channel.send_json({"op": "finished"})
    if await channel.receive_json() != {"op": "finished"}:
        raise ProtocolError("KEY_CONFIRMATION_FAILED")
    channel.handshake = {
        "algorithm": algorithm, "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "sender_fingerprint": fingerprint(public_bytes(identity.public_key())),
        "receiver_fingerprint": fingerprint(peer),
        "sender_public": hello["ephemeral"], "receiver_public": remote["ephemeral"],
        "authenticated": True, "key_exchange": "X25519 / Ed25519 / HKDF-SHA256",
    }
    return channel


async def server_handshake(reader, writer, identity, peer: bytes, context: dict | None = None,
                           expected_peer_context: dict | None = None):
    hello = parse_object(await read_frame(reader, HANDSHAKE_LIMIT))
    validate_hello(hello, peer)
    validate_context(hello.get("context"), expected_peer_context)
    ephemeral = X25519PrivateKey.generate()
    remote = hello_for(identity, ephemeral, hello["algorithm"], context)
    transcript = canonical({"protocol": "securenet/v1", "sender": hello, "receiver": remote})
    await write_frame(writer, canonical({"hello": remote,
        "signature": identity.sign(b"receiver:" + transcript).hex()}))
    response = parse_object(await read_frame(reader, HANDSHAKE_LIMIT))
    verify_signature(peer, response.get("signature", ""), b"sender:" + transcript)
    try:
        secret = ephemeral.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(hello["ephemeral"])))
    except ValueError as exc:
        raise ProtocolError("INVALID_EPHEMERAL_KEY") from exc
    tx, rx = derive_ciphers(secret, transcript, hello["algorithm"], False)
    channel = Channel(reader, writer, tx, rx, {}, idle_timeout=900)
    if await channel.receive_json() != {"op": "finished"}:
        raise ProtocolError("KEY_CONFIRMATION_FAILED")
    await channel.send_json({"op": "finished"})
    return channel


async def connect(host, port, identity, peer, algorithm=ALGORITHMS[0], context: dict | None = None,
                  expected_peer_context: dict | None = None):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), TIMEOUT)
    except (OSError, TimeoutError) as exc:
        raise ProtocolError("RECEIVER_UNAVAILABLE") from exc
    try:
        return await client_handshake(reader, writer, identity, peer, algorithm, context, expected_peer_context)
    except BaseException:
        writer.close()
        await writer.wait_closed()
        raise
