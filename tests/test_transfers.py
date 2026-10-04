import asyncio
import hashlib

import pytest

from securenet.client import attack, expect, receive_file, send_file, send_message
from securenet.crypto import ALGORITHMS, FILE_CHUNK, ProtocolError
from securenet.receiver import CHUNK_SIZE


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("size", [0, 1024, 65537, 1048576, 100 * 1024 * 1024])
async def test_verified_file_roundtrip(endpoint, tmp_path, algorithm, size):
    _, _, open_channel = endpoint
    channel = await open_channel(algorithm)
    content = bytes(range(256)) * 256
    expected_hash = hashlib.sha256()

    async def chunks():
        for offset in range(0, size, CHUNK_SIZE):
            piece = content[:min(CHUNK_SIZE, size - offset)]
            expected_hash.update(piece)
            yield piece
    result = await send_file(channel, "binary.bin", size, chunks())
    assert result["source_sha256"] == result["receiver_sha256"] == expected_hash.hexdigest()
    target = tmp_path / "verified.bin"
    await receive_file(channel, result["id"], target, expected_hash.hexdigest(), size)
    with target.open("rb") as source:
        assert hashlib.file_digest(source, "sha256").hexdigest() == expected_hash.hexdigest()
    assert target.stat().st_size == size


async def test_existing_download_is_never_deleted(endpoint, tmp_path):
    _, _, open_channel = endpoint
    channel = await open_channel()

    async def chunks():
        yield b"new data"
    result = await send_file(channel, "sample.bin", 8, chunks())
    target = tmp_path / "existing.bin"
    target.write_bytes(b"keep my original work")
    with pytest.raises(FileExistsError):
        await receive_file(channel, result["id"], target, result["receiver_sha256"], 8)
    assert target.read_bytes() == b"keep my original work"


@pytest.mark.parametrize("mode", ["tamper", "replay"])
@pytest.mark.parametrize("algorithm", ALGORITHMS)
async def test_attacks_are_rejected_over_tcp(endpoint, mode, algorithm):
    _, _, open_channel = endpoint
    result = await attack(await open_channel(algorithm), mode)
    assert result["rejected"]
    if mode == "tamper":
        assert result["original"]["ciphertext"] != result["transmitted"]["ciphertext"]
    else:
        assert result["original"] == result["transmitted"]


async def test_truncated_corrupt_and_dropped_transfers_cleanup(endpoint):
    server, _, open_channel = endpoint
    for finish in ("drop", "wrong_hash", "short"):
        channel = await open_channel()
        await channel.send_json({"op": "file_begin", "name": "../unsafe.txt", "size": 10})
        expect(await channel.receive_json(), "file_ready")
        await channel.send(b"12345" if finish == "short" else b"0123456789", FILE_CHUNK)
        if finish != "drop":
            await channel.send_json({"op": "file_end", "sha256": "0" * 64})
            assert (await channel.receive_json())["op"] == "error"
        await channel.close()
    for _ in range(50):
        if not list(server.directory.iterdir()):
            break
        await asyncio.sleep(.01)
    assert not list(server.directory.iterdir())


async def test_logs_contain_events_without_message_content(endpoint, caplog):
    _, _, open_channel = endpoint
    caplog.set_level("INFO", logger="securenet.receiver")
    channel = await open_channel()
    await send_message(channel, "never-log-this-private-message")
    await channel.close()
    await asyncio.sleep(.01)
    assert "connection_opened" in caplog.text
    assert "never-log-this-private-message" not in caplog.text
    assert channel.tx.key.hex() not in caplog.text
