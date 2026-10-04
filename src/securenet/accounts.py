"""Persistent accounts, authorization, user identities, transfer metadata, and safe events."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import fingerprint, public_bytes

PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
ID_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,96}@[^@\s]{1,96}\.[^@\s]{2,64}$")
SESSION_SECONDS = 60 * 60 * 24 * 7


class AccountError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def utc_now() -> float:
    return time.time()


def normalize_username(value: str) -> str:
    return value.strip().lower()


def normalize_email(value: str) -> str:
    return value.strip().lower()


def validate_password(password: str) -> None:
    if len(password) < 10 or len(password) > 256:
        raise AccountError("PASSWORD_POLICY", "Password must contain 10–256 characters.")
    if not any(c.islower() for c in password) or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
        raise AccountError("PASSWORD_POLICY", "Password must contain a lowercase letter, uppercase letter, and number.")


class AccountStore:
    def __init__(self, database: Path, master_secret_file: Path, storage: Path,
                 max_file_size: int = 100 * 1024 * 1024, max_files: int = 100,
                 max_storage: int = 10 * 1024 * 1024 * 1024):
        self.database = database
        self.master_secret_file = master_secret_file
        self.storage = storage
        self.max_file_size = max_file_size
        self.max_files = max_files
        self.max_storage = max_storage
        self.master_secret = b""

    def initialize(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.storage.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connection() as db:
            db.executescript(SCHEMA)
            has_users = db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
        if self.master_secret_file.exists():
            self.master_secret = self.master_secret_file.read_bytes()
            if len(self.master_secret) != 32:
                raise AccountError("MASTER_SECRET_INVALID", "Account master secret must be exactly 32 bytes.")
        elif has_users:
            raise AccountError("MASTER_SECRET_MISSING", "Account master secret is missing; existing identities are locked.")
        else:
            self.master_secret_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.master_secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as target:
                self.master_secret = os.urandom(32)
                target.write(self.master_secret)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.database, timeout=20)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _row(row):
        return dict(row) if row else None

    def _new_id(self) -> str:
        return uuid.uuid4().hex

    def _new_secure_id(self, db) -> str:
        for _ in range(100):
            value = "SN-" + "".join(secrets.choice(ID_ALPHABET) for _ in range(4)) + "-" + "".join(secrets.choice(ID_ALPHABET) for _ in range(4))
            if db.execute("SELECT 1 FROM users WHERE secure_net_id = ?", (value,)).fetchone() is None:
                return value
        raise AccountError("ID_GENERATION_FAILED", "Could not generate a unique SecureNet ID.")

    def _seal(self, payload: bytes, aad: str) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(self.master_secret).encrypt(nonce, payload, aad.encode())

    def _open(self, envelope: bytes, aad: str) -> bytes:
        if len(envelope) < 28:
            raise AccountError("SECRET_INVALID", "Protected identity data is invalid.")
        try:
            return AESGCM(self.master_secret).decrypt(envelope[:12], envelope[12:], aad.encode())
        except Exception as exc:
            raise AccountError("SECRET_INVALID", "Protected identity data could not be opened.") from exc

    def register(self, full_name: str, username: str, email: str, password: str) -> dict:
        full_name = full_name.strip()
        username = normalize_username(username)
        email = normalize_email(email)
        if not 2 <= len(full_name) <= 120:
            raise AccountError("INVALID_NAME", "Full name must contain 2–120 characters.")
        if not USERNAME_RE.fullmatch(username):
            raise AccountError("INVALID_USERNAME", "Username must be 3–32 letters, numbers, or underscores.")
        if not EMAIL_RE.fullmatch(email):
            raise AccountError("INVALID_EMAIL", "Enter a valid email address.")
        validate_password(password)
        user_id = self._new_id()
        private = Ed25519PrivateKey.generate()
        private_raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        public = public_bytes(private.public_key())
        created = utc_now()
        try:
            with self.connection() as db:
                secure_id = self._new_secure_id(db)
                db.execute("""INSERT INTO users
                    (id, secure_net_id, full_name, username, email, password_hash, public_key, private_key_blob, public_key_fingerprint, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (
                    user_id, secure_id, full_name, username, email, PASSWORDS.hash(password), public,
                    self._seal(private_raw, f"identity:{user_id}"), fingerprint(public), created, created))
        except sqlite3.IntegrityError as exc:
            raise AccountError("ACCOUNT_EXISTS", "Username or email is already registered.") from exc
        self.event(user_id, None, "REGISTRATION_SUCCESS", "info", {})
        return self.public_user(user_id)

    def authenticate(self, login: str, password: str) -> dict:
        login = login.strip().lower()
        with self.connection() as db:
            row = db.execute("SELECT * FROM users WHERE username = ? OR email = ?", (login, login)).fetchone()
        if not row:
            self.event(None, None, "LOGIN_FAILED", "warning", {"reason": "unknown_login"})
            raise AccountError("LOGIN_FAILED", "Login details are incorrect.")
        try:
            valid = PASSWORDS.verify(row["password_hash"], password)
        except (VerificationError, VerifyMismatchError, InvalidHashError):
            valid = False
        if not valid:
            self.event(row["id"], None, "LOGIN_FAILED", "warning", {"reason": "invalid_password"})
            raise AccountError("LOGIN_FAILED", "Login details are incorrect.")
        if PASSWORDS.check_needs_rehash(row["password_hash"]):
            with self.connection() as db:
                db.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", (PASSWORDS.hash(password), utc_now(), row["id"]))
        self.event(row["id"], None, "LOGIN_SUCCESS", "info", {})
        return self.public_user(row["id"])

    def create_session(self, user_id: str) -> tuple[str, str]:
        raw_token, raw_csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
        with self.connection() as db:
            db.execute("INSERT INTO auth_sessions (token_hash, user_id, csrf_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                       (hashlib.sha256(raw_token.encode()).hexdigest(), user_id, hashlib.sha256(raw_csrf.encode()).hexdigest(), utc_now(), utc_now() + SESSION_SECONDS))
        return raw_token, raw_csrf

    def session(self, token: str | None) -> dict | None:
        if not token:
            return None
        with self.connection() as db:
            row = db.execute("""SELECT u.* FROM auth_sessions s JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = ? AND s.expires_at > ?""", (hashlib.sha256(token.encode()).hexdigest(), utc_now())).fetchone()
        return self._row(row)

    def csrf_valid(self, token: str | None, csrf: str | None) -> bool:
        if not token or not csrf:
            return False
        with self.connection() as db:
            return db.execute("SELECT 1 FROM auth_sessions WHERE token_hash = ? AND csrf_hash = ? AND expires_at > ?",
                              (hashlib.sha256(token.encode()).hexdigest(), hashlib.sha256(csrf.encode()).hexdigest(), utc_now())).fetchone() is not None

    def rotate_csrf(self, token: str | None) -> str | None:
        if not token:
            return None
        csrf = secrets.token_urlsafe(32)
        with self.connection() as db:
            result = db.execute("UPDATE auth_sessions SET csrf_hash = ? WHERE token_hash = ? AND expires_at > ?",
                                (hashlib.sha256(csrf.encode()).hexdigest(), hashlib.sha256(token.encode()).hexdigest(), utc_now()))
            if result.rowcount != 1:
                return None
        return csrf

    def delete_session(self, token: str | None) -> None:
        if token:
            with self.connection() as db:
                db.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (hashlib.sha256(token.encode()).hexdigest(),))

    def public_user(self, user_id: str) -> dict:
        with self.connection() as db:
            row = db.execute("SELECT id, secure_net_id, full_name, username, email, public_key, public_key_fingerprint, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise AccountError("USER_NOT_FOUND", "User account was not found.")
        result = self._row(row)
        result["public_key"] = bytes(result["public_key"]).hex()
        return result

    def load_identity(self, user_id: str) -> Ed25519PrivateKey:
        with self.connection() as db:
            row = db.execute("SELECT private_key_blob FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise AccountError("USER_NOT_FOUND", "User account was not found.")
        try:
            return Ed25519PrivateKey.from_private_bytes(self._open(bytes(row["private_key_blob"]), f"identity:{user_id}"))
        except ValueError as exc:
            raise AccountError("IDENTITY_INVALID", "User cryptographic identity is invalid.") from exc

    def public_key(self, user_id: str) -> bytes:
        with self.connection() as db:
            row = db.execute("SELECT public_key FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise AccountError("USER_NOT_FOUND", "User account was not found.")
        return bytes(row["public_key"])

    def find_by_secure_id(self, secure_net_id: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT id, secure_net_id, username, public_key, public_key_fingerprint FROM users WHERE secure_net_id = ?", (secure_net_id.strip().upper(),)).fetchone()
        if not row:
            return None
        result = self._row(row)
        result["public_key"] = bytes(result["public_key"]).hex()
        return result

    def stats(self, user_id: str) -> dict:
        with self.connection() as db:
            files = db.execute("SELECT COUNT(*) count, COALESCE(SUM(size), 0) bytes FROM files WHERE owner_id = ? AND status = 'verified'", (user_id,)).fetchone()
            sent = db.execute("SELECT COUNT(*) count FROM transfers WHERE sender_id = ?", (user_id,)).fetchone()["count"]
            received = db.execute("SELECT COUNT(*) count FROM transfers WHERE receiver_id = ?", (user_id,)).fetchone()["count"]
            verified = db.execute("SELECT COUNT(*) count FROM transfers WHERE (sender_id = ? OR receiver_id = ?) AND status = 'verified'", (user_id, user_id)).fetchone()["count"]
            rejected = db.execute("SELECT COUNT(*) count FROM transfers WHERE (sender_id = ? OR receiver_id = ?) AND status = 'rejected'", (user_id, user_id)).fetchone()["count"]
            tampering = db.execute("SELECT COUNT(*) count FROM security_events WHERE user_id = ? AND event_type LIKE '%TAMPER%'", (user_id,)).fetchone()["count"]
        return {"files_stored": files["count"], "storage_bytes": files["bytes"], "files_sent": sent,
                "files_received": received, "successful_transfers": verified,
                "rejected_transfers": rejected, "tampering_events": tampering}

    def create_file(self, owner_id: str, file_id: str, original_filename: str, storage_name: str,
                    size: int, mime_type: str, sha256: str, algorithm: str | None, wrapped_key: bytes) -> dict:
        created = utc_now()
        with self.connection() as db:
            db.execute("""INSERT INTO files
                (id, owner_id, original_filename, storage_name, size, mime_type, sha256, encryption_algorithm, wrapped_key, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', ?)""", (file_id, owner_id, original_filename, storage_name, size, mime_type, sha256, algorithm, wrapped_key, created))
        return self.public_file(self.file(file_id, owner_id))

    @staticmethod
    def public_file(record: dict | None) -> dict | None:
        if not record:
            return None
        return {key: value for key, value in record.items() if key not in {"wrapped_key", "storage_name", "owner_id", "status"}}

    def file(self, file_id: str, owner_id: str) -> dict | None:
        with self.connection() as db:
            return self._row(db.execute("SELECT * FROM files WHERE id = ? AND owner_id = ? AND status = 'verified'", (file_id, owner_id)).fetchone())

    def list_files(self, owner_id: str) -> list[dict]:
        with self.connection() as db:
            return [self._row(row) for row in db.execute("SELECT id, original_filename, size, mime_type, sha256, encryption_algorithm, created_at FROM files WHERE owner_id = ? AND status = 'verified' ORDER BY created_at DESC", (owner_id,))]

    def received_files(self, owner_id: str) -> list[dict]:
        with self.connection() as db:
            rows = db.execute("""SELECT f.id, f.original_filename, f.size, f.mime_type, f.sha256,
                f.encryption_algorithm, f.created_at, t.id transfer_id, u.secure_net_id sender_secure_id,
                u.username sender_username, t.status transfer_status
                FROM files f JOIN transfers t ON t.receiver_file_id = f.id
                JOIN users u ON u.id = t.sender_id
                WHERE f.owner_id = ? AND f.status = 'verified' ORDER BY f.created_at DESC""", (owner_id,))
            return [self._row(row) for row in rows]

    def storage_used(self, owner_id: str) -> int:
        with self.connection() as db:
            return int(db.execute("SELECT COALESCE(SUM(size), 0) bytes FROM files WHERE owner_id = ? AND status = 'verified'", (owner_id,)).fetchone()["bytes"])

    def delete_file(self, file_id: str, owner_id: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT storage_name FROM files WHERE id = ? AND owner_id = ?", (file_id, owner_id)).fetchone()
            if not row:
                return None
            db.execute("UPDATE files SET status = 'deleted' WHERE id = ? AND owner_id = ?", (file_id, owner_id))
        return self._row(row)

    def file_key(self, record: dict) -> bytes:
        return self._open(bytes(record["wrapped_key"]), f"file:{record['id']}")

    def wrap_file_key(self, file_id: str, key: bytes) -> bytes:
        return self._seal(key, f"file:{file_id}")

    def create_transfer(self, values: dict) -> None:
        with self.connection() as db:
            db.execute("""INSERT INTO transfers
              (id, sender_id, receiver_id, file_id, receiver_file_id, original_filename, size, algorithm, key_exchange, status, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (values["id"], values["sender_id"], values["receiver_id"], values.get("file_id"), values.get("receiver_file_id"), values["original_filename"], values["size"], values["algorithm"], values.get("key_exchange", "X25519 / HKDF-SHA256"), values.get("status", "started"), utc_now()))

    def finish_transfer(self, transfer_id: str, values: dict) -> None:
        with self.connection() as db:
            db.execute("""UPDATE transfers SET file_id = ?, receiver_file_id = ?, status = ?, source_sha256 = ?, receiver_sha256 = ?,
              total_chunks = ?, verified_chunks = ?, matched_bytes = ?, duration_ms = ?, transfer_speed = ?, completed_at = ?, receipt_json = ? WHERE id = ?""",
                       (values.get("file_id"), values.get("receiver_file_id"), values["status"], values.get("source_sha256"), values.get("receiver_sha256"), values.get("total_chunks", 0), values.get("verified_chunks", 0), values.get("matched_bytes", 0), values.get("duration_ms"), values.get("transfer_speed"), utc_now() if values["status"] == "verified" else None, json.dumps(values.get("receipt", {}), separators=(",", ":")), transfer_id))

    def transfers(self, user_id: str) -> list[dict]:
        with self.connection() as db:
            rows = db.execute("""SELECT t.*, s.secure_net_id sender_secure_id, r.secure_net_id receiver_secure_id
                FROM transfers t JOIN users s ON s.id=t.sender_id JOIN users r ON r.id=t.receiver_id
                WHERE t.sender_id = ? OR t.receiver_id = ? ORDER BY t.created_at DESC""", (user_id, user_id))
            return [self._row(row) for row in rows]

    def transfer(self, transfer_id: str, user_id: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("""SELECT t.*, s.secure_net_id sender_secure_id, r.secure_net_id receiver_secure_id
              FROM transfers t JOIN users s ON s.id=t.sender_id JOIN users r ON r.id=t.receiver_id
              WHERE t.id = ? AND (t.sender_id = ? OR t.receiver_id = ?)""", (transfer_id, user_id, user_id)).fetchone()
        return self._row(row)

    def event(self, user_id: str | None, transfer_id: str | None, event_type: str, severity: str, metadata: dict) -> None:
        safe = {str(k): v for k, v in metadata.items() if k not in {"password", "private_key", "secret", "session_key", "plaintext", "raw_key"}}
        with self.connection() as db:
            db.execute("INSERT INTO security_events (id, user_id, transfer_id, event_type, severity, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (self._new_id(), user_id, transfer_id, event_type, severity, json.dumps(safe, separators=(",", ":")), utc_now()))

    def events(self, user_id: str, limit=100) -> list[dict]:
        with self.connection() as db:
            rows = list(db.execute("SELECT id, transfer_id, event_type, severity, metadata_json, created_at FROM security_events WHERE user_id = ? ORDER BY created_at DESC LIMIT ?", (user_id, min(max(limit, 1), 200))))
        output = []
        for row in rows:
            value = self._row(row)
            value["metadata"] = json.loads(value.pop("metadata_json"))
            output.append(value)
        return output


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, secure_net_id TEXT NOT NULL UNIQUE, full_name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  public_key BLOB NOT NULL, private_key_blob BLOB NOT NULL, public_key_fingerprint TEXT NOT NULL,
  created_at REAL NOT NULL, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_sessions (
  token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_hash TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_filename TEXT NOT NULL, storage_name TEXT NOT NULL UNIQUE, size INTEGER NOT NULL,
  mime_type TEXT NOT NULL, sha256 TEXT NOT NULL, encryption_algorithm TEXT,
  wrapped_key BLOB NOT NULL, status TEXT NOT NULL, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS transfers (
  id TEXT PRIMARY KEY, sender_id TEXT NOT NULL REFERENCES users(id), receiver_id TEXT NOT NULL REFERENCES users(id),
  file_id TEXT REFERENCES files(id), receiver_file_id TEXT REFERENCES files(id), original_filename TEXT NOT NULL,
  size INTEGER NOT NULL, algorithm TEXT NOT NULL, key_exchange TEXT NOT NULL, status TEXT NOT NULL,
  source_sha256 TEXT, receiver_sha256 TEXT, total_chunks INTEGER DEFAULT 0, verified_chunks INTEGER DEFAULT 0,
  matched_bytes INTEGER DEFAULT 0, duration_ms REAL, transfer_speed REAL, created_at REAL NOT NULL,
  completed_at REAL, receipt_json TEXT
);
CREATE TABLE IF NOT EXISTS security_events (
  id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE, transfer_id TEXT REFERENCES transfers(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL, severity TEXT NOT NULL, metadata_json TEXT NOT NULL, created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON auth_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id, status);
CREATE INDEX IF NOT EXISTS idx_transfers_users ON transfers(sender_id, receiver_id, created_at);
CREATE INDEX IF NOT EXISTS idx_events_user ON security_events(user_id, created_at);
"""
