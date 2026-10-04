"""TCP receiver: authenticate every record before acting on it."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import tempfile
import uuid
from pathlib import Path

from .crypto import FILE_CHUNK, JSON_RECORD, ProtocolError
from .network import parse_object, server_handshake

CHUNK_SIZE = 64 * 1024
MAX_FILE = 100 * 1024 * 1024
logger = logging.getLogger("securenet.receiver")


class Receiver:
    def __init__(self, identity, peer: bytes, directory: Path, max_clients=32, context=None,
                 expected_peer_context=None, retain_files=False):
        self.identity, self.peer, self.directory = identity, peer, directory
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_clients = max_clients
        self.connections = set()
        self.tasks = set()
        self.server = None
        self.context = context
        self.expected_peer_context = expected_peer_context
        self.retain_files = retain_files
        self.completed = {}

    async def start(self, host="127.0.0.1", port=9000):
        self.server = await asyncio.start_server(self.handle, host, port)
        return self.server.sockets[0].getsockname()[1]

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for writer in list(self.connections):
            writer.close()
        if self.tasks:
            await asyncio.gather(*list(self.tasks), return_exceptions=True)

    async def handle(self, reader, writer):
        if len(self.connections) >= self.max_clients:
            writer.close()
            await writer.wait_closed()
            return
        self.connections.add(writer)
        task = asyncio.current_task()
        self.tasks.add(task)
        channel, active, files = None, None, {}
        logger.info("connection_opened")
        try:
            channel = await server_handshake(reader, writer, self.identity, self.peer,
                                             self.context, self.expected_peer_context)
            while True:
                kind, raw = await channel.receive()
                if kind == FILE_CHUNK:
                    if not active or len(raw) > CHUNK_SIZE or not raw:
                        raise ProtocolError("UNEXPECTED_FILE_CHUNK")
                    if active["received"] + len(raw) > active["size"]:
                        raise ProtocolError("FILE_SIZE_REJECTED")
                    active["handle"].write(raw)
                    active["hash"].update(raw)
                    active["chunk_hashes"].append(hashlib.sha256(raw).hexdigest())
                    active["received"] += len(raw)
                    continue
                if kind != JSON_RECORD:
                    raise ProtocolError("UNEXPECTED_RECORD_TYPE")
                message = parse_object(raw)
                op = message.get("op")
                if active and op != "file_end":
                    raise ProtocolError("TRANSFER_IN_PROGRESS")
                if op == "message":
                    text = message.get("text")
                    if not isinstance(text, str) or len(text.encode()) > 16 * 1024:
                        raise ProtocolError("MESSAGE_SIZE_REJECTED")
                    await channel.send_json({"op": "message_ack", "text": text,
                                             "sha256": hashlib.sha256(text.encode()).hexdigest()})
                elif op == "file_begin":
                    size = message.get("size")
                    name = message.get("name")
                    if type(size) is not int or not 0 <= size <= MAX_FILE or len(files) >= 3:
                        raise ProtocolError("FILE_SIZE_REJECTED")
                    if not isinstance(name, str) or len(name) > 200:
                        raise ProtocolError("INVALID_FILENAME")
                    handle = tempfile.NamedTemporaryFile(dir=self.directory, delete=False)
                    active = {"handle": handle, "path": Path(handle.name), "name": name,
                              "size": size, "received": 0, "hash": hashlib.sha256(),
                              "chunk_hashes": []}
                    await channel.send_json({"op": "file_ready"})
                elif op == "file_end":
                    if not active or active["received"] != active["size"]:
                        raise ProtocolError("INCOMPLETE_FILE")
                    if message.get("sha256") != active["hash"].hexdigest():
                        raise ProtocolError("FILE_HASH_MISMATCH")
                    active["handle"].close()
                    file_id = uuid.uuid4().hex
                    files[file_id] = active
                    self.completed[file_id] = active
                    await channel.send_json({"op": "file_ack", "id": file_id,
                        "sha256": active["hash"].hexdigest(), "size": active["size"],
                        "chunks": len(active["chunk_hashes"]),
                        "chunk_hashes": active["chunk_hashes"]})
                    active = None
                    logger.info("file_verified")
                elif op == "download":
                    item = files.get(message.get("id"))
                    if item is None:
                        raise ProtocolError("FILE_NOT_FOUND")
                    await channel.send_json({"op": "download_begin", "size": item["size"]})
                    with item["path"].open("rb") as source:
                        while chunk := source.read(CHUNK_SIZE):
                            await channel.send(chunk, FILE_CHUNK)
                    await channel.send_json({"op": "download_end", "sha256": item["hash"].hexdigest()})
                else:
                    raise ProtocolError("UNKNOWN_OPERATION")
        except ProtocolError as exc:
            logger.info("connection_ended code=%s", str(exc))
            if channel and str(exc) != "CONNECTION_CLOSED":
                try:
                    await channel.send_json({"op": "error", "code": str(exc)})
                except (ProtocolError, ConnectionError):
                    pass
        except (ConnectionError, OSError, ValueError, TypeError):
            logger.info("connection_ended code=INVALID_CONNECTION")
        finally:
            if active:
                active["handle"].close()
                active["path"].unlink(missing_ok=True)
            if not self.retain_files:
                for item in files.values():
                    item["path"].unlink(missing_ok=True)
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            self.connections.discard(writer)
            self.tasks.discard(task)

    def cleanup_completed(self):
        for item in self.completed.values():
            item["path"].unlink(missing_ok=True)
        self.completed.clear()
