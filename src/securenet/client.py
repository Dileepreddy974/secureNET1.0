"""Shared CLI/web client operations, including isolated wire-level attack demos."""

import asyncio
import hashlib
import os
import time

from .crypto import FILE_CHUNK, HEADER, ProtocolError, canonical
from .network import connect, parse_object, read_frame, write_frame
from .receiver import CHUNK_SIZE


def expect(response: dict, operation: str):
    if response.get("op") == "error":
        raise ProtocolError(response.get("code", "RECEIVER_REJECTED"))
    if response.get("op") != operation:
        raise ProtocolError("UNEXPECTED_RESPONSE")
    return response


async def send_message(channel, text: str, emit=lambda *_: None):
    payload = canonical({"op": "message", "text": text})
    started = time.perf_counter()
    emit("encode", {"bytes": len(text.encode())})
    # Separate CPU encryption timing from transport/acknowledgement latency.
    before_crypto = time.perf_counter()
    record = channel.tx.seal(payload)
    crypto_ms = (time.perf_counter() - before_crypto) * 1000
    emit("encrypt", {"bytes": len(record), "sequence": channel.tx.sequence - 1})
    await write_frame(channel.writer, record)
    emit("transmit", {"bytes": len(record) + 4})
    ack = expect(await channel.receive_json(), "message_ack")
    if ack.get("text") != text:
        raise ProtocolError("RECEIVER_CONTENT_MISMATCH")
    emit("verify", {"verified": True})
    return {"text": ack["text"], "sha256": ack["sha256"],
            "plaintext_hex": text.encode()[:512].hex(), "record": channel.tx.inspect(record),
            "encryption_ms": round(crypto_ms, 4),
            "round_trip_ms": round((time.perf_counter() - started) * 1000, 3),
            "payload_bytes": len(payload), "message_bytes": len(text.encode())}


async def send_file(channel, name, size, chunks, emit=lambda *_: None):
    started = time.perf_counter()
    await channel.send_json({"op": "file_begin", "name": name, "size": size})
    expect(await channel.receive_json(), "file_ready")
    digest, total, count = hashlib.sha256(), 0, 0
    first_record = None
    source_chunk_hashes = []
    async for raw in chunks:
        for offset in range(0, len(raw), CHUNK_SIZE):
            chunk = raw[offset:offset + CHUNK_SIZE]
            total += len(chunk)
            if total > size:
                raise ProtocolError("FILE_SIZE_REJECTED")
            digest.update(chunk)
            source_chunk_hashes.append(hashlib.sha256(chunk).hexdigest())
            record = await channel.send(chunk, FILE_CHUNK)
            count += 1
            if first_record is None:
                first_record = channel.tx.inspect(record)
            emit("file_chunk", {"chunk": count, "sent": total, "total": size})
    if total != size:
        raise ProtocolError("INCOMPLETE_FILE")
    await channel.send_json({"op": "file_end", "sha256": digest.hexdigest()})
    ack = expect(await channel.receive_json(), "file_ack")
    if ack["sha256"] != digest.hexdigest() or ack["size"] != total:
        raise ProtocolError("FILE_HASH_MISMATCH")
    elapsed = time.perf_counter() - started
    emit("file_verified", {"chunks": count, "bytes": total})
    return {"id": ack["id"], "name": name, "size": size, "chunks": count,
            "source_sha256": digest.hexdigest(), "receiver_sha256": ack["sha256"],
            "source_chunk_hashes": source_chunk_hashes,
            "receiver_chunk_hashes": ack.get("chunk_hashes", []),
            "duration_ms": round(elapsed * 1000, 3),
            "throughput_mbps": round(total / max(elapsed, 1e-9) / 1024 / 1024, 2),
            "record": first_record, "verified": True}


async def receive_file(channel, file_id, path, expected_hash, expected_size):
    await channel.send_json({"op": "download", "id": file_id})
    begin = expect(await channel.receive_json(), "download_begin")
    if begin.get("size") != expected_size:
        raise ProtocolError("FILE_SIZE_REJECTED")
    total, digest = 0, hashlib.sha256()
    # Open exclusively before cleanup handling: never delete an existing user file.
    target = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
    try:
        with target:
            while total < expected_size:
                kind, chunk = await channel.receive()
                if kind != FILE_CHUNK or not chunk or len(chunk) > CHUNK_SIZE:
                    raise ProtocolError("INVALID_FILE_CHUNK")
                total += len(chunk)
                if total > expected_size:
                    raise ProtocolError("FILE_SIZE_REJECTED")
                target.write(chunk)
                digest.update(chunk)
        end = expect(await channel.receive_json(), "download_end")
        if end.get("sha256") != digest.hexdigest() or digest.hexdigest() != expected_hash:
            raise ProtocolError("FILE_HASH_MISMATCH")
    except BaseException:
        path.unlink(missing_ok=True)
        raise


async def attack(channel, mode):
    original = channel.tx.seal(canonical({"op": "message", "text": "CONTROLLED ATTACK SAMPLE"}))
    if mode == "tamper":
        damaged = bytearray(original)
        damaged[HEADER.size] ^= 1
        transmitted = bytes(damaged)
        await write_frame(channel.writer, transmitted)
    elif mode == "replay":
        transmitted = original
        await write_frame(channel.writer, original)
        expect(await channel.receive_json(), "message_ack")
        await write_frame(channel.writer, original)
    else:
        raise ProtocolError("UNKNOWN_ATTACK")
    response = await channel.receive_json()
    expected = "AUTHENTICATION_FAILED" if mode == "tamper" else "REPLAY_OR_SEQUENCE_REJECTED"
    if response != {"op": "error", "code": expected}:
        raise ProtocolError("ATTACK_DEMONSTRATION_FAILED")
    return {"mode": mode, "rejected": True, "code": expected,
            "original": channel.tx.inspect(original), "transmitted": channel.tx.inspect(transmitted),
            "changed_offset": HEADER.size if mode == "tamper" else None}


async def handshake_attack(host, port, identity, peer, algorithm):
    """Local interception proxy substitutes the real receiver's ephemeral key."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from .crypto import public_bytes

    tasks = set()

    async def intercept(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        upstream = None
        try:
            remote, upstream = await asyncio.open_connection(host, port)
            await write_frame(upstream, await read_frame(reader))
            response = parse_object(await read_frame(remote))
            response["hello"]["ephemeral"] = public_bytes(X25519PrivateKey.generate().public_key()).hex()
            # Keep the genuine signature: the altered transcript must fail verification.
            await write_frame(writer, canonical(response))
            await reader.read(1)
        finally:
            for connection in (upstream, writer):
                if connection:
                    connection.close()
                    await connection.wait_closed()
            tasks.discard(task)

    proxy = await asyncio.start_server(intercept, "127.0.0.1", 0)
    try:
        channel = await connect("127.0.0.1", proxy.sockets[0].getsockname()[1], identity, peer, algorithm)
        await channel.close()
        raise ProtocolError("ATTACK_DEMONSTRATION_FAILED")
    except ProtocolError as exc:
        if str(exc) != "HANDSHAKE_SIGNATURE_REJECTED":
            raise
        return {"mode": "handshake", "rejected": True, "code": str(exc)}
    finally:
        proxy.close()
        await proxy.wait_closed()
        if tasks:
            await asyncio.gather(*list(tasks), return_exceptions=True)
