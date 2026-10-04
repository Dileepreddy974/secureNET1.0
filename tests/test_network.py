import asyncio
import json
import os
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from securenet.client import handshake_attack, send_message
from securenet.crypto import ALGORITHMS, MAX_RECORD, ProtocolError, canonical, public_bytes
from securenet.network import (client_handshake, connect, hello_for, parse_object, read_frame,
                               validate_hello, verify_signature, write_frame)


async def test_fragmented_and_coalesced_frames():
    reader = asyncio.StreamReader()
    first, second = b"hello", b"next"
    wire = struct.pack("!I", len(first)) + first + struct.pack("!I", len(second)) + second

    async def feed():
        for chunk in (wire[:1], wire[1:3], wire[3:7], wire[7:]):
            reader.feed_data(chunk)
            await asyncio.sleep(0)
    task = asyncio.create_task(feed())
    assert await read_frame(reader) == first
    assert await read_frame(reader) == second
    await task


@pytest.mark.parametrize("size", [0, MAX_RECORD + 1])
async def test_frame_limits(size):
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack("!I", size))
    with pytest.raises(ProtocolError, match="FRAME_SIZE"):
        await read_frame(reader)


async def test_eof_timeout_and_invalid_write():
    reader = asyncio.StreamReader()
    reader.feed_data(b"\x00\x00")
    reader.feed_eof()
    with pytest.raises(ProtocolError, match="CONNECTION_CLOSED"):
        await read_frame(reader)
    with pytest.raises(ProtocolError, match="TIMEOUT"):
        await read_frame(asyncio.StreamReader(), idle_timeout=.001)
    with pytest.raises(ProtocolError, match="FRAME_SIZE"):
        await write_frame(None, b"")


@pytest.mark.parametrize("raw", [b"[1]", b"null", b"invalid", b"\xff"])
def test_invalid_json(raw):
    with pytest.raises(ProtocolError, match="INVALID_MESSAGE"):
        parse_object(raw)


def test_hello_validation(identities):
    hello = hello_for(identities["sender"], X25519PrivateKey.generate(), ALGORITHMS[0])
    pin = identities["receiver_pin"]
    validate_hello(hello, pin)
    for patch, expected in (({"version": 2}, "UNSUPPORTED"), ({"algorithm": "none"}, "UNSUPPORTED"),
                            ({"identity": os.urandom(32).hex()}, "IDENTITY"),
                            ({"ephemeral": "aa"}, "INVALID"), ({"challenge": None}, "INVALID")):
        with pytest.raises(ProtocolError, match=expected):
            validate_hello({**hello, **patch}, pin)
    with pytest.raises(ProtocolError, match="INVALID"):
        validate_hello({}, pin)
    for signature in ("00", [], "invalid"):
        with pytest.raises(ProtocolError, match="SIGNATURE"):
            verify_signature(pin, signature, b"data")


@pytest.mark.parametrize("algorithm", ALGORITHMS)
async def test_authenticated_tcp_and_fresh_keys(endpoint, algorithm):
    _, _, open_channel = endpoint
    first, second = await open_channel(algorithm), await open_channel(algorithm)
    assert first.tx.key != second.tx.key
    assert first.handshake["authenticated"]
    assert first.tx.sequence == first.rx.sequence == 1  # encrypted key confirmation
    response = await send_message(first, "real TCP / హలో 🔒")
    assert response["text"] == "real TCP / హలో 🔒"
    assert response["record"]["sequence"] == 1
    assert response["round_trip_ms"] > 0


async def test_untrusted_server_and_client_rejected(endpoint, identities):
    _, port, _ = endpoint
    with pytest.raises(ProtocolError, match="IDENTITY"):
        await connect("127.0.0.1", port, identities["sender"], os.urandom(32))
    with pytest.raises(ProtocolError, match="CONNECTION_CLOSED"):
        await connect("127.0.0.1", port, Ed25519PrivateKey.generate(), identities["sender_pin"])
    with pytest.raises(ProtocolError, match="UNSUPPORTED"):
        await connect("127.0.0.1", port, identities["sender"], identities["sender_pin"], "none")


async def test_real_key_substitution_proxy(endpoint, identities):
    _, port, _ = endpoint
    result = await handshake_attack("127.0.0.1", port, identities["sender"], identities["sender_pin"], ALGORITHMS[0])
    assert result["code"] == "HANDSHAKE_SIGNATURE_REJECTED"


async def test_ten_simultaneous_clients_and_concurrent_record_sends(endpoint):
    _, _, open_channel = endpoint

    async def visitor(index):
        channel = await open_channel()
        result = await send_message(channel, f"visitor {index}")
        assert result["text"] == f"visitor {index}"
    await asyncio.gather(*(visitor(i) for i in range(10)))
    channel = await open_channel()
    await asyncio.gather(*(channel.send_json({"op": "message", "text": str(i)}) for i in range(10)))
    seen = {(await channel.receive_json())["text"] for _ in range(10)}
    assert seen == {str(i) for i in range(10)}


@pytest.mark.parametrize("variation", ["downgrade", "malformed", "bad_signature"])
async def test_malformed_server_handshakes(endpoint, identities, variation):
    async def fake(reader, writer):
        try:
            hello = json.loads(await read_frame(reader))
            remote = hello_for(identities["receiver"], X25519PrivateKey.generate(), hello["algorithm"])
            if variation == "downgrade":
                remote["algorithm"] = ALGORITHMS[1]
            if variation == "malformed":
                remote = []
            await write_frame(writer, canonical({"hello": remote, "signature": "00"}))
        finally:
            writer.close()
            await writer.wait_closed()
    server = await asyncio.start_server(fake, "127.0.0.1", 0)
    try:
        with pytest.raises(ProtocolError):
            await connect("127.0.0.1", server.sockets[0].getsockname()[1], identities["sender"], identities["sender_pin"])
    finally:
        server.close()
        await server.wait_closed()
