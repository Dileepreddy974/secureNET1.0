# Repository audit and completed extension plan

## Current architecture

- React 19 / TypeScript / Vite, tab routing in `frontend/src/main.tsx`, separate `HashLab.tsx`, CSS design tokens and self-hosted fonts. Six labs: messages, hashing, files, attacks, benchmarks, guide.
- FastAPI in `api.py`; Typer CLI in `cli.py`. Python 3.12+, cryptography library, asyncio TCP.
- Demo sessions remain in-memory `DemoSession` objects, while the account workspace now has SQLite users/sessions/files/transfers/events. Both flows use separate opaque HttpOnly cookies, CSRF checks, same-origin requests, expiry, operation limits, and SSE queues for the original lab events.
- Temporary files belong to demo connections and are deleted on disconnect. Docker tmpfs is deliberately transient. Demo identity keys persist in role-specific named volumes; account identities/files/database persist in separate named volumes and the account unlock secret is mounted separately.
- REST routes: `/api/health`, `/api/session`, `/api/events`, `/api/messages`, `/api/files`, `/api/files/{id}`, `/api/attacks`, `/api/hashes`, `/api/benchmarks`.
- Tests: crypto primitives/record rejection, handshake/framing, concurrent clients, 100 MiB file round trips, cleanup, API session ownership/CSRF, account registration/storage/IDOR/transfers/tampering, hashing vectors, desktop/mobile browser workflows.
- Docker Compose: initializer, isolated TCP receiver, web/sender, optional Caddy HTTPS proxy. Existing environment settings cover data/key paths, receiver address, HTTPS/origin, trusted proxy, and web port.

## Current cryptographic flow

Pinned Ed25519 endpoint identities sign a transcript containing fresh ephemeral X25519 public keys, random challenges, roles, protocol version, and selected algorithm. X25519 + HKDF-SHA256 derive independent directional keys/nonce prefixes. Encrypted finished records confirm possession. AES-256-GCM or ChaCha20-Poly1305 records bind sequence, type, length, and transcript; counter reuse/replay and invalid tags are rejected. No secret keys are exposed in receipts or UI.

## Current file flow

Encrypted begin metadata → 64 KiB authenticated chunks → encrypted final SHA-256 manifest → receiver independent chunk/hash/length check → authenticated acknowledgement → independently verified temporary browser download. Account transfers additionally compare every byte and commit sender/receiver vault files only after verification. Existing success text uses “Byte for byte”.

## Current authentication flow

Demo visitor cookie authenticates access to a temporary session, not a person. TCP endpoint pin/signature verification authenticates the two service identities. Account authentication is separate from the anonymous teaching-session cookie, preserving the lab API and CLI contract. Account sessions store only hashed opaque tokens and use Argon2id password hashes plus CSRF tokens.

## Current attack simulations

Real ciphertext bit flip, duplicate accepted record replay, localhost interception proxy substitution of the receiver ephemeral public key, private-file temporary-copy tampering, and chunk comparison. Hashing uses MD5 as historical education and SHA-256 for modern fingerprints. Benchmarks use real timings. Education includes bounded Caesar, Vigenère, XOR, RSA-OAEP, Ed25519, and ECC/X25519 demonstrations.

## Files modified

`api.py` (account router/lifecycle and body limits), `network.py` (signed transfer context), `receiver.py` (context/event hooks and chunk acknowledgements), `client.py` (per-chunk verification), `pyproject.toml` (Argon2), frontend entry point (account/education workspace navigation), Docker/configuration, README, reports, and tests.

## Files created

`accounts.py` (SQLite schema, identities, auth sessions, events), `vault.py` (envelope-encrypted file storage), `user_transfer.py` (reuse of TCP sender/receiver), `education.py` (bounded teaching exercises), `AccountPanel.tsx`, `EducationLab.tsx`, account/education CSS, account/storage/transfer/IDOR/browser tests, and multi-user architecture documentation.

## Implementation sequence — complete

1. Accounts/Argon2id/revocable sessions/unique SecureNet IDs, verify with focused tests.
2. Profiles, encrypted file ownership/quota operations, receiver lookup/confirmation, protected Ed25519 identity storage.
3. Bind transfer context into the existing handshake; use per-user identities and fresh X25519 keys on real loopback TCP endpoints hosted by the application. Existing external demo receiver stays available to the lab and CLI.
4. Transfer in authenticated chunks, return verified bytes, compare byte-for-byte and by chunk, commit the receiver-owned encrypted file only after all checks pass.
5. Persist history/receipts and security events. Add controlled temporary-copy and encrypted-chunk attacks plus classical/RSA educational tools.
6. Account dashboard, owned files, send/receive/history/events/profile interfaces integrated with current labs.
7. Full regressions, two-user IDOR/transfer tests, production build, Docker Compose health and two-user smoke testing, and documentation.

Verification currently completed: `74 passed` in the Python suite, `8 passed` in the desktop/mobile Playwright suite, successful frontend production build, healthy Compose `web` and `receiver` services, and a two-user Docker transfer with AES-GCM, verified download, and tamper detection.

## Risks and design decisions

- Hosted key custody is explicit: the server can decrypt account keys/files. User Ed25519 keys sign fresh X25519 exchanges; signing keys are never passed to X25519 APIs.
- SQLite contains password hashes, encrypted private-key envelopes, wrapped per-file keys, metadata, and hashed auth tokens; raw account/session/storage secrets are not stored there.
- A separate persistent master-secret mount unlocks identities and wrapped file keys. Losing it loses access; existing data must never cause silent master-key regeneration.
- Server-side ownership checks apply before every file/history/event operation. Receiver confirmation is tied to the logged-in sender and receiver fingerprint.
- Quotas and file mutations use ordered per-user locks in this single-worker architecture. A multi-worker deployment would require database-backed job/lock coordination.
- Interrupted transfers never publish a verified receiver file. Cleanup and restart recovery distinguish committed ciphertext from staging files.
- Plaintext is transient in restricted work directories during comparison; it is not served as static content or persisted in event logs.
- SQLite/owned files and the master secret need persistent Docker volumes; existing demo tmpfs remains transient.
- Preserve all existing labs/API/CLI and cryptographic tests. All new UI values derive from backend operations, not staged success states.
