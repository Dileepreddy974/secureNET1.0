# SecureNet multi-user architecture

## Account lifecycle

Registration validates name, username, email, and password policy. Passwords are stored as Argon2id PHC hashes. A unique human-facing `SN-XXXX-XXXX` identifier is generated independently from the SQLite primary key. Login creates an opaque HttpOnly `securenet_account` cookie; only a SHA-256 token hash and CSRF-token hash are stored. Login, logout, expiry, and invalid credentials emit safe event records.

Each user receives an Ed25519 signing identity. The raw private key is wrapped with AES-256-GCM under the separately mounted 32-byte account master secret before it is stored in SQLite. The database stores the public key and SHA-256 fingerprint. The UI shows the fingerprint and “protected” state; it never returns the private key or any session key.

The current hosted demo can access endpoint plaintext by design. Account cryptographic identities are protected at rest, but this is not client-side end-to-end encryption against the host. Full client-held private keys would require a separate browser/CLI key custody protocol.

## Database and storage

SQLite tables:

- `users`: account fields, Argon2id hash, public key, encrypted private-key envelope, fingerprint.
- `auth_sessions`: hashed session/CSRF tokens and expiry.
- `files`: owner, safe original name, encrypted storage name, size/MIME, SHA-256, algorithm, wrapped per-file key, status.
- `transfers`: sender/receiver, file IDs, algorithm, key exchange, hashes, chunks, matched bytes, metrics, receipt, status.
- `security_events`: user-owned safe audit metadata.

Files are stored under `/account/storage/<owner-id>/<file-id>.snf` in Docker. The file format uses a magic header, random GCM nonce, streaming AES-GCM ciphertext, and an authentication tag. Each file key is random and wrapped with the account master secret using an account/file-specific associated-data label. The SQLite database, storage volume, and master-secret volume are persistent in Compose. Demo temporary data remains transient.

The server enforces per-file, file-count, and byte-storage quotas. Filenames are reduced to a display basename; storage names are random IDs. Download, integrity, delete, history, events, and transfer routes require the authenticated user and a server-side owner/participant check. Frontend IDs are never treated as ownership proof.

## User-to-user transfer

`POST /api/account/transfers` accepts an authenticated sender, a receiver SecureNet ID, algorithm, and a bounded upload. The API resolves the receiver server-side and creates a transfer record before sending. A loopback TCP `Receiver` is started with the receiver’s Ed25519 private identity and the sender’s public-key pin. The sender connects with the sender identity and the receiver public key.

The handshake context binds:

```text
purpose: user-transfer
transfer_id: TRX-....
sender_id: SN-....
receiver_id: SN-....
```

Both sides require the same context in their signed transcript. Fresh ephemeral X25519 keys derive directional session keys with HKDF-SHA256. File records are AES-256-GCM or ChaCha20-Poly1305 protected with strict sequence and nonce rules. A 64 KiB chunk is hashed independently at the receiver.

After the final manifest, the service compares:

1. source and receiver file sizes;
2. whole-file SHA-256 values;
3. every source/receiver chunk hash;
4. every byte in a bounded streaming comparison.

Only a fully verified receiver staging file is encrypted into the receiver’s private vault. The source is encrypted into the sender’s private vault. Failed or interrupted staging files are removed and no file is marked verified. The receipt contains IDs, algorithms, hashes, chunk counts, matched bytes, duration, speed, and status—never keys. The account UI renders a bounded chunk-integrity panel with `✓ MATCH` or `! UNVERIFIED` for each displayed chunk alongside the aggregate result.

## Account API

```text
POST /api/account/register
POST /api/account/login
GET  /api/account/me
POST /api/account/logout
GET  /api/account/users/{secure_net_id}
GET  /api/account/files
POST /api/account/files
GET  /api/account/files/{id}/download
GET  /api/account/files/{id}/integrity
DELETE /api/account/files/{id}
POST /api/account/transfers
GET  /api/account/received
GET  /api/account/transfers
GET  /api/account/transfers/{id}/receipt
GET  /api/account/events
POST /api/account/attacks/file
```

Existing anonymous educational endpoints, CLI commands, demo TCP receiver, hashing lab, benchmarks, and attack lab remain available.

## Controlled attacks

- File tamper: decrypt a selected private file into a disposable staging copy, flip a byte, calculate source/modified SHA-256 and chunk hashes, compare bytes, emit `TAMPERING_DETECTED`, and delete the copy. The verified stored file is not changed.
- Ciphertext tamper: existing TCP attack changes one protected record byte; GCM/Poly1305 rejects it.
- Replay: existing TCP attack sends an accepted record twice; sequence state rejects the duplicate.
- Key substitution: existing interceptor changes the signed ephemeral key; Ed25519 transcript verification rejects the session.
- Chunk corruption is represented by the file attack’s independent chunk hash comparison and can be extended to a receiver test proxy without changing the production receiver.

## Educational algorithms

The Education tab/API runs bounded real demonstrations of Caesar, Vigenère, XOR, RSA-OAEP, Ed25519 signatures, and an X25519 explanation. Classical techniques are labeled insecure. RSA’s private key is generated only inside the operation and is never returned. X25519 is labeled key exchange; Ed25519 is labeled signing; AES-GCM/ChaCha20-Poly1305 remain the file/message encryption algorithms.
