"""Account-to-account transfers over the existing authenticated TCP protocol."""

from __future__ import annotations

import asyncio
import hashlib
import mimetypes
import shutil
import time
import uuid
from pathlib import Path

from .accounts import AccountError, AccountStore
from .client import send_file
from .crypto import ALGORITHMS, ProtocolError, public_bytes
from .network import connect
from .receiver import CHUNK_SIZE, Receiver
from .vault import compare_bytes, encrypt_file, sha256_file


def safe_name(name: str) -> str:
    value = Path(name.replace("\\", "/")).name
    value = "".join(character for character in value if character.isprintable())[:200]
    return value or "transfer.bin"


def _storage_path(store: AccountStore, owner_id: str, file_id: str) -> Path:
    return store.storage / owner_id / f"{file_id}.snf"


def _store_encrypted(store: AccountStore, owner_id: str, source: Path, name: str,
                     mime: str, digest: str, size: int, algorithm: str | None) -> dict:
    file_id = uuid.uuid4().hex
    key = __import__("os").urandom(32)
    storage_path = _storage_path(store, owner_id, file_id)
    encrypt_file(source, storage_path, key)
    try:
        return store.create_file(owner_id, file_id, safe_name(name), storage_path.name,
                                 size, mime or "application/octet-stream", digest, algorithm,
                                 store.wrap_file_key(file_id, key))
    except BaseException:
        storage_path.unlink(missing_ok=True)
        raise


def store_private_file(store: AccountStore, owner_id: str, source: Path, name: str,
                       mime_type: str | None, algorithm: str | None = None) -> dict:
    digest, size = sha256_file(source)
    if size > store.max_file_size:
        raise AccountError("FILE_TOO_LARGE", "This file exceeds the configured file-size limit.")
    if store.storage_used(owner_id) + size > store.max_storage:
        raise AccountError("STORAGE_LIMIT", "The storage quota would be exceeded.")
    if len(store.list_files(owner_id)) >= store.max_files:
        raise AccountError("FILE_LIMIT", "The file limit has been reached.")
    return _store_encrypted(store, owner_id, source, name, mime_type or mimetypes.guess_type(name)[0] or "application/octet-stream", digest, size, algorithm)


async def transfer_file(store: AccountStore, sender_id: str, receiver_secure_id: str,
                        source: Path, filename: str, mime_type: str | None, algorithm: str,
                        emit=lambda *_: None) -> dict:
    if algorithm not in ALGORITHMS:
        raise AccountError("UNSUPPORTED_ALGORITHM", "Choose AES-256-GCM or ChaCha20-Poly1305.")
    receiver = store.find_by_secure_id(receiver_secure_id)
    if not receiver:
        raise AccountError("RECEIVER_NOT_FOUND", "No registered user has that SecureNet ID.")
    if receiver["id"] == sender_id:
        raise AccountError("SELF_TRANSFER", "Choose another registered receiver.")
    digest, size = sha256_file(source)
    if size > store.max_file_size:
        raise AccountError("FILE_TOO_LARGE", "This file exceeds the configured file-size limit.")
    if store.storage_used(sender_id) + size > store.max_storage:
        raise AccountError("STORAGE_LIMIT", "The sender storage quota would be exceeded.")
    if len(store.list_files(sender_id)) >= store.max_files:
        raise AccountError("FILE_LIMIT", "The sender file limit has been reached.")
    if store.storage_used(receiver["id"]) + size > store.max_storage:
        raise AccountError("RECEIVER_STORAGE_LIMIT", "The receiver storage quota would be exceeded.")
    if len(store.list_files(receiver["id"])) >= store.max_files:
        raise AccountError("RECEIVER_FILE_LIMIT", "The receiver file limit has been reached.")

    sender = store.public_user(sender_id)
    transfer_id = "TRX-" + uuid.uuid4().hex[:4].upper() + "-" + uuid.uuid4().hex[:4].upper()
    context = {"purpose": "user-transfer", "transfer_id": transfer_id,
               "sender_id": sender["secure_net_id"], "receiver_id": receiver["secure_net_id"]}
    store.create_transfer({"id": transfer_id, "sender_id": sender_id, "receiver_id": receiver["id"],
                           "original_filename": safe_name(filename), "size": size, "algorithm": algorithm})
    store.event(sender_id, transfer_id, "TRANSFER_STARTED", "info", {"receiver_id": receiver["secure_net_id"], "size": size, "algorithm": algorithm})
    store.event(receiver["id"], transfer_id, "TRANSFER_STARTED", "info", {"sender_id": sender["secure_net_id"], "size": size, "algorithm": algorithm})
    started = time.perf_counter()
    service = None
    temporary_receiver = None
    try:
        receiver_identity = store.load_identity(receiver["id"])
        sender_identity = store.load_identity(sender_id)
        staging = store.storage / ".transfers" / transfer_id
        staging.mkdir(parents=True, exist_ok=True, mode=0o700)
        service = Receiver(receiver_identity, store.public_key(sender_id), staging,
                           context=context, expected_peer_context=context, retain_files=True)
        port = await service.start("127.0.0.1", 0)
        emit("key_exchange_started", {"transfer_id": transfer_id, "receiver_id": receiver["secure_net_id"]})
        channel = await connect("127.0.0.1", port, sender_identity, receiver["public_key"] and bytes.fromhex(receiver["public_key"]), algorithm, context, context)
        try:
            async def chunks():
                with source.open("rb") as input_file:
                    while chunk := input_file.read(CHUNK_SIZE):
                        yield chunk

            result = await send_file(channel, safe_name(filename), size, chunks(), emit)
            emit("authentication_verified", {"transfer_id": transfer_id})
            receiver_item = service.completed.get(result["id"])
            if not receiver_item:
                raise ProtocolError("RECEIVER_FILE_NOT_AVAILABLE")
            temporary_receiver = receiver_item["path"]
            receiver_digest, receiver_size = sha256_file(temporary_receiver)
            comparison = compare_bytes(source, temporary_receiver)
            source_chunks = result.get("source_chunk_hashes", [])
            receiver_chunks = result.get("receiver_chunk_hashes", [])
            verified_chunks = sum(a == b for a, b in zip(source_chunks, receiver_chunks))
            chunks_match = len(source_chunks) == len(receiver_chunks) == verified_chunks
            verified = receiver_size == size and receiver_digest == digest and comparison["identical"] and chunks_match
            sender_file = receiver_file = None
            if verified:
                sender_file = _store_encrypted(store, sender_id, source, filename, mime_type or mimetypes.guess_type(filename)[0] or "application/octet-stream", digest, size, algorithm)
                receiver_file = _store_encrypted(store, receiver["id"], temporary_receiver, filename, mime_type or mimetypes.guess_type(filename)[0] or "application/octet-stream", receiver_digest, receiver_size, algorithm)
            duration = (time.perf_counter() - started) * 1000
            receipt = {"transfer_id": transfer_id, "sender_id": sender["secure_net_id"], "receiver_id": receiver["secure_net_id"],
                       "file": safe_name(filename), "size": size, "algorithm": algorithm,
                       "key_exchange": "X25519", "key_derivation": "HKDF-SHA256", "authentication": "Ed25519",
                       "source_sha256": digest, "receiver_sha256": receiver_digest, "total_chunks": len(source_chunks),
                       "verified_chunks": verified_chunks, "matched_bytes": comparison["matched_bytes"],
                       "total_compared_bytes": comparison["total_bytes"], "byte_for_byte": comparison["identical"],
                       "chunk_integrity": chunks_match, "status": "VERIFIED" if verified else "FAILED"}
            store.finish_transfer(transfer_id, {"file_id": sender_file["id"] if sender_file else None,
                "receiver_file_id": receiver_file["id"] if receiver_file else None,
                "status": "verified" if verified else "rejected", "source_sha256": digest,
                "receiver_sha256": receiver_digest, "total_chunks": len(source_chunks),
                "verified_chunks": verified_chunks, "matched_bytes": comparison["matched_bytes"],
                "duration_ms": round(duration, 3), "transfer_speed": round(size / max(duration / 1000, 1e-9) / 1024 / 1024, 2), "receipt": receipt})
            if verified:
                store.event(sender_id, transfer_id, "TRANSFER_COMPLETED", "info", {"receiver_id": receiver["secure_net_id"], "sha256": digest, "chunks": verified_chunks})
                store.event(receiver["id"], transfer_id, "TRANSFER_COMPLETED", "info", {"sender_id": sender["secure_net_id"], "sha256": receiver_digest, "chunks": verified_chunks})
                return {"transfer": store.transfer(transfer_id, sender_id), "receipt": receipt}
            store.event(sender_id, transfer_id, "HASH_MISMATCH", "critical", {"source_sha256": digest, "receiver_sha256": receiver_digest})
            store.event(receiver["id"], transfer_id, "TRANSFER_REJECTED", "critical", {"reason": "integrity_check_failed"})
            raise ProtocolError("TRANSFER_INTEGRITY_FAILED")
        finally:
            await channel.close()
    except BaseException as exc:
        if not isinstance(exc, AccountError):
            try:
                store.finish_transfer(transfer_id, {"status": "rejected", "receipt": {"transfer_id": transfer_id, "status": "REJECTED", "reason": str(exc)[:80]}})
                store.event(sender_id, transfer_id, "TRANSFER_REJECTED", "critical", {"reason": type(exc).__name__})
                store.event(receiver["id"], transfer_id, "TRANSFER_REJECTED", "critical", {"reason": type(exc).__name__})
            except Exception:
                pass
        raise
    finally:
        if service:
            await service.stop()
            service.cleanup_completed()
        shutil.rmtree(store.storage / ".transfers" / transfer_id, ignore_errors=True)
