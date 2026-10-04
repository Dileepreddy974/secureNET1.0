"""Same-origin demo API. Every visitor owns an isolated authenticated TCP channel."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import secrets
import shutil
import tempfile
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from . import client
from .accounts import AccountError, AccountStore
from .benchmark import run_benchmark
from .crypto import ALGORITHMS, ProtocolError, initialize_identities, load_identity
from .education import caesar, overview as education_overview, rsa_demo, signature_demo, vigenere, xor_bytes
from .hashing import compare_hashes
from .network import connect
from .receiver import Receiver
from .user_transfer import safe_name, store_private_file, transfer_file
from .vault import compare_bytes, decrypt_file, sha256_file

logger = logging.getLogger("securenet.api")


@dataclass
class Settings:
    data: Path = field(default_factory=lambda: Path(os.getenv("SECURENET_DATA_DIR", ".data")))
    keys: Path = field(default_factory=lambda: Path(os.getenv("SECURENET_KEYS_DIR", ".data/keys")))
    password: Path = field(default_factory=lambda: Path(os.getenv("SECURENET_PASSWORD_FILE", ".data/key-password")))
    host: str = field(default_factory=lambda: os.getenv("SECURENET_RECEIVER_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("SECURENET_RECEIVER_PORT", "9000")))
    embedded: bool = field(default_factory=lambda: os.getenv("SECURENET_EMBEDDED", "1") == "1")
    secure_cookie: bool = field(default_factory=lambda: os.getenv("SECURENET_HTTPS", "0") == "1")
    origin: str = field(default_factory=lambda: os.getenv("SECURENET_PUBLIC_ORIGIN", ""))
    max_upload: int = 10 * 1024 * 1024
    max_sessions: int = 20
    idle_seconds: int = 900
    accounts_db: Path = field(default_factory=lambda: Path(os.getenv("SECURENET_ACCOUNTS_DB", ".data/accounts/securenet.db")))
    account_secret: Path = field(default_factory=lambda: Path(os.getenv("SECURENET_ACCOUNT_SECRET_FILE", ".data/accounts/master-secret")))
    account_storage: Path = field(default_factory=lambda: Path(os.getenv("SECURENET_ACCOUNT_STORAGE", ".data/accounts/storage")))
    account_max_file_size: int = field(default_factory=lambda: int(os.getenv("SECURENET_MAX_FILE_SIZE", str(100 * 1024 * 1024))))
    account_max_files: int = field(default_factory=lambda: int(os.getenv("SECURENET_MAX_FILES_PER_USER", "100")))
    account_max_storage: int = field(default_factory=lambda: int(os.getenv("SECURENET_MAX_STORAGE_PER_USER", str(10 * 1024 * 1024 * 1024))))


@dataclass
class DemoSession:
    channel: object
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    created: float = field(default_factory=time.monotonic)
    touched: float = field(default_factory=time.monotonic)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    events: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=128))
    files: dict = field(default_factory=dict)
    requests: deque = field(default_factory=deque)
    streaming: bool = False
    closed: bool = False
    operations: int = 0

    def emit(self, stage, detail):
        event = {"stage": stage, "detail": detail, "timestamp": time.time()}
        if self.events.full():
            self.events.get_nowait()
        self.events.put_nowait(event)

    async def close(self):
        if self.closed:
            return
        self.closed = True
        await self.channel.close()
        for entry in self.files.values():
            entry["path"].unlink(missing_ok=True)
        self.emit("closed", {})


class SessionRequest(BaseModel):
    algorithm: str = ALGORITHMS[0]


class MessageRequest(BaseModel):
    text: str = Field(min_length=1, max_length=16 * 1024)


class AttackRequest(BaseModel):
    mode: str


class RegistrationRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    username: str = Field(min_length=3, max_length=32)
    email: str = Field(min_length=5, max_length=160)
    password: str = Field(min_length=10, max_length=256)
    confirm_password: str = Field(min_length=10, max_length=256)


class LoginRequest(BaseModel):
    login: str = Field(min_length=3, max_length=160)
    password: str = Field(min_length=1, max_length=256)


class EducationRequest(BaseModel):
    technique: str
    text: str = Field(max_length=4096)
    key: str = Field(default="", max_length=128)
    shift: int = Field(default=3, ge=-1000, le=1000)


class FileAttackRequest(BaseModel):
    file_id: str
    mode: str = "file_tamper"


class HashRequest(BaseModel):
    original: str = Field(max_length=8192)
    changed: str = Field(max_length=8192)


def create_app(settings: Settings | None = None):
    settings = settings or Settings()
    sessions: dict[str, DemoSession] = {}
    create_lock = asyncio.Lock()
    creation_times = deque()
    benchmark_lock = asyncio.Lock()
    benchmark_cache = None

    @asynccontextmanager
    async def lifespan(app):
        event_logger = logging.getLogger("securenet")
        if not event_logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
            event_logger.addHandler(handler)
        event_logger.setLevel(logging.INFO)
        settings.data.mkdir(parents=True, exist_ok=True, mode=0o700)
        downloads = settings.data / "downloads"
        downloads.mkdir(exist_ok=True, mode=0o700)
        # Dedicated transient directory; crash leftovers have no valid session owner.
        for leftover in downloads.glob("*.download"):
            leftover.unlink()
        receiver = None
        if settings.embedded:
            initialize_identities(settings.keys, settings.password)
            receiver = Receiver(load_identity(settings.keys / "receiver/identity.pem", settings.password),
                                (settings.keys / "receiver/peer.pub").read_bytes(), settings.data / "received")
            settings.port = await receiver.start(settings.host, settings.port)
        app.state.identity = load_identity(settings.keys / "sender/identity.pem", settings.password)
        app.state.peer = (settings.keys / "sender/peer.pub").read_bytes()
        accounts = AccountStore(settings.accounts_db, settings.account_secret, settings.account_storage,
                                settings.account_max_file_size, settings.account_max_files, settings.account_max_storage)
        accounts.initialize()
        app.state.accounts = accounts
        app.state.settings = settings

        async def cleanup():
            while True:
                await asyncio.sleep(15)
                now = time.monotonic()
                for token, session in list(sessions.items()):
                    if session.closed or (not session.lock.locked() and
                        (now - session.touched > settings.idle_seconds or now - session.created > 1800)):
                        sessions.pop(token, None)
                        await session.close()

        cleaner = asyncio.create_task(cleanup())
        try:
            yield
        finally:
            cleaner.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cleaner
            await asyncio.gather(*(s.close() for s in sessions.values()))
            if receiver:
                await receiver.stop()

    app = FastAPI(title="SecureNet Lab", lifespan=lifespan, docs_url=None, redoc_url=None)

    @app.middleware("http")
    async def boundaries(request: Request, call_next):
        if request.url.path.startswith("/api/"):
            origin = request.headers.get("origin")
            allowed = settings.origin or f"{request.url.scheme}://{request.headers.get('host', '')}"
            if origin and origin != allowed:
                return JSONResponse({"detail": "Origin rejected"}, status_code=403)
            if request.method in ("POST", "PUT", "DELETE"):
                try:
                    length = int(request.headers.get("content-length", "0"))
                except ValueError:
                    return JSONResponse({"detail": "Invalid request length"}, status_code=400)
                # JSON escaping can expand a valid 16 KiB message up to sixfold.
                if request.url.path in ("/api/files",):
                    maximum = settings.max_upload
                elif request.url.path in ("/api/account/files", "/api/account/transfers"):
                    maximum = settings.account_max_file_size + 2 * 1024 * 1024
                else:
                    maximum = 128 * 1024
                if length < 0 or length > maximum:
                    return JSONResponse({"detail": "Request too large"}, status_code=413)
                # Require bounded lengths for JSON requests; raw uploads enforce streaming limits too.
                if request.method in ("POST", "PUT") and "content-length" not in request.headers:
                    return JSONResponse({"detail": "Content-Length required"}, status_code=411)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def owner(request: Request, mutate=False):
        session = sessions.get(request.cookies.get("securenet_session", ""))
        now = time.monotonic()
        if not session or session.closed or now - session.touched > settings.idle_seconds or now - session.created > 1800:
            raise HTTPException(401, "Session expired. Start a new connection.")
        if mutate:
            supplied = request.headers.get("x-csrf-token", "")
            if not secrets.compare_digest(supplied, session.csrf):
                raise HTTPException(403, "Session token rejected")
            while session.requests and now - session.requests[0] > 60:
                session.requests.popleft()
            if len(session.requests) >= 30:
                raise HTTPException(429, "Limit: 30 operations per minute")
            session.requests.append(now)
        session.touched = now
        return session

    def account_owner(request: Request, mutate=False) -> dict:
        account_store: AccountStore = request.app.state.accounts
        token = request.cookies.get("securenet_account")
        user = account_store.session(token)
        if not user:
            raise HTTPException(401, "Please log in to use account features.")
        if mutate and not account_store.csrf_valid(token, request.headers.get("x-account-csrf")):
            raise HTTPException(403, "Account session token rejected")
        return user

    def account_response(payload: dict, token: str, csrf: str):
        response = JSONResponse(payload)
        response.set_cookie("securenet_account", token, httponly=True, secure=settings.secure_cookie,
                            samesite="strict", max_age=7 * 24 * 60 * 60, path="/")
        response.headers["X-Account-CSRF"] = csrf
        return response

    async def save_upload(upload: UploadFile, destination: Path, maximum: int) -> tuple[int, str]:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        digest, size = __import__("hashlib").sha256(), 0
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as target:
                while chunk := await upload.read(64 * 1024):
                    size += len(chunk)
                    if size > maximum:
                        raise HTTPException(413, "File exceeds the configured size limit.")
                    digest.update(chunk)
                    target.write(chunk)
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        finally:
            await upload.close()
        return size, digest.hexdigest()

    def encrypted_download(store: AccountStore, record: dict):
        temporary = store.storage / ".downloads" / f"{uuid.uuid4().hex}.clear"
        temporary.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        decrypt_file(store.storage / record["owner_id"] / record["storage_name"], temporary, store.file_key(record))
        return FileResponse(temporary, filename=record["original_filename"], media_type=record["mime_type"],
                            background=BackgroundTask(temporary.unlink, missing_ok=True))

    @asynccontextmanager
    async def operation(session):
        if session.lock.locked():
            raise HTTPException(409, "A transfer is already running")
        async with session.lock:
            try:
                yield
                session.operations += 1
                session.touched = time.monotonic()
            except (ProtocolError, ConnectionError, OSError) as exc:
                code = str(exc) if isinstance(exc, ProtocolError) else "CONNECTION_FAILED"
                await session.close()
                logger.info("operation_failed code=%s", code)
                raise HTTPException(409, code) from exc
            except BaseException:
                await session.close()
                raise

    @app.post("/api/account/register")
    async def register(body: RegistrationRequest, request: Request):
        if body.password != body.confirm_password:
            raise HTTPException(422, "Passwords do not match.")
        try:
            user = request.app.state.accounts.register(body.full_name, body.username, body.email, body.password)
            token, csrf = request.app.state.accounts.create_session(user["id"])
            return account_response({"user": user, "stats": request.app.state.accounts.stats(user["id"])}, token, csrf)
        except AccountError as exc:
            raise HTTPException(409 if exc.code == "ACCOUNT_EXISTS" else 422, exc.message) from exc

    @app.post("/api/account/login")
    async def login(body: LoginRequest, request: Request):
        try:
            user = request.app.state.accounts.authenticate(body.login, body.password)
            token, csrf = request.app.state.accounts.create_session(user["id"])
            return account_response({"user": user, "stats": request.app.state.accounts.stats(user["id"])}, token, csrf)
        except AccountError as exc:
            raise HTTPException(401 if exc.code == "LOGIN_FAILED" else 422, exc.message) from exc

    @app.get("/api/account/me")
    async def account_me(request: Request):
        user = account_owner(request)
        response = JSONResponse({"user": request.app.state.accounts.public_user(user["id"]), "stats": request.app.state.accounts.stats(user["id"])})
        if not request.headers.get("x-account-csrf"):
            csrf = request.app.state.accounts.rotate_csrf(request.cookies.get("securenet_account"))
            if csrf:
                response.headers["X-Account-CSRF"] = csrf
        return response

    @app.post("/api/account/logout")
    async def logout(request: Request):
        account_owner(request, True)
        request.app.state.accounts.delete_session(request.cookies.get("securenet_account"))
        response = JSONResponse({"logged_out": True})
        response.delete_cookie("securenet_account", path="/")
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/account/users/{secure_net_id}")
    async def find_receiver(secure_net_id: str, request: Request):
        account_owner(request)
        found = request.app.state.accounts.find_by_secure_id(secure_net_id)
        if not found:
            raise HTTPException(404, "Receiver SecureNet ID was not found.")
        return {"secure_net_id": found["secure_net_id"], "username": found["username"],
                "public_key_fingerprint": found["public_key_fingerprint"], "public_key_available": True}

    @app.get("/api/account/files")
    async def account_files(request: Request):
        user = account_owner(request)
        store = request.app.state.accounts
        return {"files": store.list_files(user["id"]), "used_bytes": store.storage_used(user["id"]),
                "max_bytes": store.max_storage, "max_files": store.max_files}

    @app.post("/api/account/files")
    async def account_file_upload(request: Request, file: UploadFile = File(...)):
        user = account_owner(request, True)
        store: AccountStore = request.app.state.accounts
        staging = store.storage / ".uploads" / f"{uuid.uuid4().hex}.upload"
        try:
            await save_upload(file, staging, store.max_file_size)
            record = store_private_file(store, user["id"], staging, safe_name(file.filename or "upload.bin"), file.content_type)
            store.event(user["id"], None, "FILE_UPLOADED", "info", {"file_id": record["id"], "size": record["size"], "sha256": record["sha256"]})
            return {"file": record, "stats": store.stats(user["id"])}
        except AccountError as exc:
            raise HTTPException(413 if exc.code in {"FILE_TOO_LARGE", "STORAGE_LIMIT", "FILE_LIMIT"} else 422, exc.message) from exc
        finally:
            staging.unlink(missing_ok=True)

    @app.get("/api/account/files/{file_id}/download")
    async def account_file_download(file_id: str, request: Request):
        user = account_owner(request)
        record = request.app.state.accounts.file(file_id, user["id"])
        if not record:
            raise HTTPException(404, "File not found in your private storage.")
        request.app.state.accounts.event(user["id"], None, "FILE_DOWNLOADED", "info", {"file_id": file_id})
        return encrypted_download(request.app.state.accounts, record)

    @app.get("/api/account/files/{file_id}/integrity")
    async def account_file_integrity(file_id: str, request: Request):
        user = account_owner(request)
        store = request.app.state.accounts
        record = store.file(file_id, user["id"])
        if not record:
            raise HTTPException(404, "File not found in your private storage.")
        temporary = store.storage / ".downloads" / f"{uuid.uuid4().hex}.integrity"
        temporary.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            decrypt_file(store.storage / user["id"] / record["storage_name"], temporary, store.file_key(record))
            digest, size = sha256_file(temporary)
            return {"filename": record["original_filename"], "size": size, "stored_sha256": record["sha256"],
                    "calculated_sha256": digest, "verified": digest == record["sha256"]}
        finally:
            temporary.unlink(missing_ok=True)

    @app.delete("/api/account/files/{file_id}")
    async def account_file_delete(file_id: str, request: Request):
        user = account_owner(request, True)
        store = request.app.state.accounts
        deleted = store.delete_file(file_id, user["id"])
        if not deleted:
            raise HTTPException(404, "File not found in your private storage.")
        (store.storage / user["id"] / deleted["storage_name"]).unlink(missing_ok=True)
        store.event(user["id"], None, "FILE_DELETED", "info", {"file_id": file_id})
        return {"deleted": True}

    @app.post("/api/account/attacks/file")
    async def account_file_attack(body: FileAttackRequest, request: Request):
        user = account_owner(request, True)
        store: AccountStore = request.app.state.accounts
        record = store.file(body.file_id, user["id"])
        if not record:
            raise HTTPException(404, "File not found in your private storage.")
        if body.mode not in {"file_tamper", "chunk_corruption"}:
            raise HTTPException(422, "Unknown file attack simulation.")
        original = store.storage / user["id"] / record["storage_name"]
        directory = store.storage / ".attacks"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        clear = directory / f"{uuid.uuid4().hex}.original"
        modified = directory / f"{uuid.uuid4().hex}.modified"
        try:
            decrypt_file(original, clear, store.file_key(record))
            shutil.copyfile(clear, modified)
            with modified.open("r+b") as target:
                if record["size"]:
                    target.seek(0)
                    target.write(bytes([target.read(1)[0] ^ 1]))
                else:
                    target.write(b"controlled-tamper")
            original_hash, original_size = sha256_file(clear)
            modified_hash, modified_size = sha256_file(modified)
            comparison = compare_bytes(clear, modified)
            chunk_size = 64 * 1024
            original_chunks, modified_chunks = [], []
            with clear.open("rb") as left, modified.open("rb") as right:
                while True:
                    a, b = left.read(chunk_size), right.read(chunk_size)
                    if not a and not b:
                        break
                    original_chunks.append(hashlib.sha256(a).hexdigest())
                    modified_chunks.append(hashlib.sha256(b).hexdigest())
            changed_chunks = [index + 1 for index, (a, b) in enumerate(zip(original_chunks, modified_chunks)) if a != b]
            store.event(user["id"], None, "TAMPERING_DETECTED", "warning", {"file_id": body.file_id, "mode": body.mode, "modified_chunks": changed_chunks})
            return {"file_id": body.file_id, "mode": body.mode, "rejected": True, "status": "FILE INTEGRITY FAILED",
                    "source_sha256": original_hash, "modified_sha256": modified_hash, "source_size": original_size,
                    "modified_size": modified_size, "modified_bytes": comparison["different_bytes"],
                    "modified_chunks": changed_chunks, "source_chunks": len(original_chunks), "verified_chunks": 0,
                    "message": "SHA-256 mismatch. The modified temporary copy was rejected and not stored as verified."}
        finally:
            clear.unlink(missing_ok=True)
            modified.unlink(missing_ok=True)

    @app.post("/api/account/transfers")
    async def account_transfer(request: Request, receiver_id: str = Form(...), algorithm: str = Form("AES-256-GCM"), file: UploadFile = File(...)):
        user = account_owner(request, True)
        store: AccountStore = request.app.state.accounts
        staging = store.storage / ".uploads" / f"{uuid.uuid4().hex}.transfer"
        try:
            await save_upload(file, staging, store.max_file_size)
            result = await transfer_file(store, user["id"], receiver_id, staging, safe_name(file.filename or "transfer.bin"), file.content_type, algorithm)
            return result
        except AccountError as exc:
            raise HTTPException(404 if exc.code == "RECEIVER_NOT_FOUND" else 409 if exc.code.endswith("LIMIT") else 422, exc.message) from exc
        except ProtocolError as exc:
            raise HTTPException(409, str(exc)) from exc
        finally:
            staging.unlink(missing_ok=True)

    @app.get("/api/account/received")
    async def received_files(request: Request):
        user = account_owner(request)
        return {"files": request.app.state.accounts.received_files(user["id"])}

    @app.get("/api/account/transfers")
    async def account_transfers(request: Request):
        user = account_owner(request)
        return {"transfers": request.app.state.accounts.transfers(user["id"])}

    @app.get("/api/account/transfers/{transfer_id}/receipt")
    async def transfer_receipt(transfer_id: str, request: Request):
        user = account_owner(request)
        result = request.app.state.accounts.transfer(transfer_id, user["id"])
        if not result:
            raise HTTPException(404, "Transfer not found in your history.")
        result["receipt"] = json.loads(result.get("receipt_json") or "{}")
        result.pop("receipt_json", None)
        return result

    @app.get("/api/account/events")
    async def account_events(request: Request):
        user = account_owner(request)
        return {"events": request.app.state.accounts.events(user["id"])}

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "service": "securenet", "version": "0.1.0"}

    @app.get("/api/education")
    async def education():
        return education_overview()

    @app.post("/api/education/demo")
    async def education_demo(body: EducationRequest, request: Request):
        # The educational lab is available without an account and has strict bounded input.
        try:
            if body.technique == "caesar":
                encrypted = caesar(body.text, body.shift)
                return {"technique": "Caesar cipher", "educational_only": True, "input": body.text, "encrypted": encrypted, "decrypted": caesar(encrypted, body.shift, True)}
            if body.technique == "vigenere":
                encrypted = vigenere(body.text, body.key)
                return {"technique": "Vigenère cipher", "educational_only": True, "input": body.text, "encrypted": encrypted, "decrypted": vigenere(encrypted, body.key, True)}
            if body.technique == "xor":
                result = xor_bytes(body.text, body.key)
                return {"technique": "XOR", "educational_only": True, "input": body.text, **result}
            if body.technique == "rsa":
                return {"technique": "RSA-OAEP", "educational_only": True, **rsa_demo(body.text)}
            if body.technique == "ed25519":
                return {"technique": "Ed25519", "educational_only": True, **signature_demo(body.text)}
            if body.technique == "ecc":
                return {"technique": "ECC / X25519", "educational_only": True, "message": "X25519 is a key-exchange technique. It derives shared session material; AES-GCM or ChaCha20-Poly1305 encrypts the data."}
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        raise HTTPException(422, "Unknown educational technique")

    @app.post("/api/session")
    async def start_session(body: SessionRequest, request: Request):
        if body.algorithm not in ALGORITHMS:
            raise HTTPException(422, "Unsupported algorithm")
        async with create_lock:
            now = time.monotonic()
            while creation_times and now - creation_times[0][0] > 60:
                creation_times.popleft()
            if len(creation_times) >= 40:
                raise HTTPException(429, "Demo connection capacity reached. Try again shortly.")
            remote_ip = request.client.host if request.client else "unknown"
            if sum(1 for _, ip in creation_times if ip == remote_ip) >= 12:
                raise HTTPException(429, "Limit: 12 new connections per minute per address")
            old_token = request.cookies.get("securenet_session", "")
            old = sessions.get(old_token)
            if old and not old.lock.locked() and (old.closed or now - old.touched > settings.idle_seconds or now - old.created > 1800):
                await old.close()
                sessions.pop(old_token, None)
                old = None
            if old:
                if old.lock.locked():
                    raise HTTPException(409, "Finish the active operation first")
                supplied = request.headers.get("x-csrf-token", "")
                if not secrets.compare_digest(old.csrf, supplied):
                    raise HTTPException(403, "Session token rejected")
                await old.close()
                sessions.pop(old_token, None)
            if len(sessions) >= settings.max_sessions:
                raise HTTPException(429, "All demo sessions are busy. Try again shortly.")
            creation_times.append((now, remote_ip))
            try:
                channel = await connect(settings.host, settings.port, app.state.identity, app.state.peer, body.algorithm)
            except (ProtocolError, OSError) as exc:
                raise HTTPException(503, "Could not authenticate the TCP receiver") from exc
            token = secrets.token_urlsafe(32)
            session = DemoSession(channel)
            sessions[token] = session
            session.emit("handshake", {"authenticated": True, "duration_ms": channel.handshake["duration_ms"]})
            response = JSONResponse({"csrf": session.csrf, "handshake": channel.handshake,
                                     "max_upload": settings.max_upload})
            response.set_cookie("securenet_session", token, httponly=True, secure=settings.secure_cookie,
                                samesite="strict", max_age=1800, path="/api")
            return response

    @app.get("/api/session")
    async def current_session(request: Request):
        session = owner(request)
        return {"csrf": session.csrf, "handshake": session.channel.handshake, "max_upload": settings.max_upload}

    @app.delete("/api/session")
    async def end_session(request: Request):
        session = owner(request, True)
        if session.lock.locked():
            raise HTTPException(409, "Finish the active operation first")
        await session.close()
        sessions.pop(request.cookies.get("securenet_session", ""), None)
        response = JSONResponse({"closed": True})
        response.delete_cookie("securenet_session", path="/api")
        return response

    @app.get("/api/events")
    async def events(request: Request):
        session = owner(request)
        if session.streaming:
            raise HTTPException(409, "This session already has an event stream")
        session.streaming = True

        async def generate():
            try:
                while not session.closed:
                    try:
                        event = await asyncio.wait_for(session.events.get(), 10)
                        yield f"data: {json.dumps(event)}\n\n"
                    except TimeoutError:
                        yield ": heartbeat\n\n"
                yield 'data: {"stage":"closed","detail":{}}\n\n'
            finally:
                session.streaming = False
        return StreamingResponse(generate(), media_type="text/event-stream",
                                 headers={"X-Accel-Buffering": "no"})

    @app.post("/api/messages")
    async def message(body: MessageRequest, request: Request):
        session = owner(request, True)
        if len(body.text.encode()) > 16 * 1024:
            raise HTTPException(413, "Message exceeds 16 KiB")
        async with operation(session):
            return await client.send_message(session.channel, body.text, session.emit)

    @app.put("/api/files")
    async def upload(request: Request, name: str = "transfer.bin"):
        session = owner(request, True)
        size = int(request.headers.get("content-length", "0"))
        if size > settings.max_upload or len(session.files) >= 3:
            raise HTTPException(413, "Limit: 10 MiB per file and 3 files per session")
        name = name.replace("\\", "/").split("/")[-1]
        name = "".join(c for c in name if c.isprintable())[:200] or "transfer.bin"
        async with operation(session):
            result = await client.send_file(session.channel, name, size, request.stream(), session.emit)
            path = settings.data / "downloads" / f"{uuid.uuid4().hex}.download"
            await client.receive_file(session.channel, result["id"], path, result["receiver_sha256"], size)
            download_id = uuid.uuid4().hex
            session.files[download_id] = {"path": path, "name": name}
            result["download_id"] = download_id
            return result

    @app.get("/api/files/{file_id}")
    async def download(file_id: str, request: Request):
        session = owner(request)
        item = session.files.get(file_id)
        if not item:
            raise HTTPException(404, "File not found in this session")
        return FileResponse(item["path"], filename=item["name"], media_type="application/octet-stream")

    @app.post("/api/attacks")
    async def attacks(body: AttackRequest, request: Request):
        session = owner(request, True)
        if body.mode not in ("tamper", "replay", "handshake"):
            raise HTTPException(422, "Unknown attack")
        async with operation(session):
            algorithm = session.channel.handshake["algorithm"]
            if body.mode == "handshake":
                result = await client.handshake_attack(settings.host, settings.port,
                    app.state.identity, app.state.peer, algorithm)
            else:
                channel = await connect(settings.host, settings.port, app.state.identity, app.state.peer, algorithm)
                try:
                    result = await client.attack(channel, body.mode)
                finally:
                    await channel.close()
            session.emit("attack_rejected", {"mode": body.mode, "code": result["code"]})
            return result

    @app.post("/api/hashes")
    async def hashes(body: HashRequest, request: Request):
        session = owner(request, True)
        try:
            result = compare_hashes(body.original, body.changed)
        except ValueError as exc:
            raise HTTPException(413, str(exc)) from exc
        session.emit("hashes_compared", {"original_bytes": result["original_bytes"],
                                        "changed_bytes": result["changed_bytes"]})
        return result

    @app.post("/api/benchmarks")
    async def benchmarks(request: Request):
        nonlocal benchmark_cache
        owner(request, True)
        if benchmark_lock.locked():
            raise HTTPException(409, "A benchmark is already running")
        async with benchmark_lock:
            if benchmark_cache and time.time() - benchmark_cache["timestamp"] < 60:
                return benchmark_cache
            benchmark_cache = await asyncio.to_thread(run_benchmark)
            return benchmark_cache

    distribution = Path(os.getenv("SECURENET_STATIC_DIR", str(Path(__file__).resolve().parents[2] / "frontend/dist")))
    if distribution.exists():
        app.mount("/", StaticFiles(directory=distribution, html=True), name="website")
    return app


app = create_app()
