# SecureNet Lab — implementation report

## Abstract

SecureNet Lab demonstrates authenticated encryption over TCP through a public-demo-ready web interface and a Python CLI. The interface exposes the learning process: plaintext encoding, nonce-based encryption, wire records, integrity verification, and recovered messages. A brutalist off-white/black/lime design keeps protocol stages, byte values, and outcomes visible.

## Implementation

The Python package separates cryptographic primitives, TCP framing/handshake, receiver behavior, client operations, API session management, hashing demonstrations, benchmarking, and CLI commands. React/TypeScript provides six workspaces: messages, hashing, files, attacks, benchmarks, and a guide. Both interfaces use the same TCP/crypto implementation.

The beginner Hashing workspace compares real MD5 and SHA-256 digests of two texts, highlights changed characters, counts changed bits, and visualizes text → UTF-8 bytes → fingerprint. Plain-language labels explain encryption as locking, decryption as unlocking, and hashing as making a one-way fingerprint. MD5 is explicitly historical and is never used to protect the network channel.

Fresh X25519 ephemeral keys establish a shared secret. Ed25519 signatures over the role-labeled transcript and pre-provisioned identity pins authenticate the endpoints. HKDF-SHA256 derives independent directional keys and nonce prefixes. AES-256-GCM and ChaCha20-Poly1305 protect application payloads with 128-bit tags. Monotonic counters and transcript-bound authenticated headers provide session-specific replay detection.

Files travel in independently authenticated chunks of at most 64 KiB. A final encrypted manifest and receiver-computed SHA-256 establish complete transfer before acknowledgement. The file download path verifies the returned bytes again. Dropped/incomplete transfers are cleaned up.

## Functional requirement mapping

| Requirement | Status / evidence |
|---|---|
| FR-1 TCP connection | Real asyncio TCP streams; separate-container smoke test |
| FR-2 authenticated key exchange | Signed ephemeral handshake and encrypted key confirmation |
| FR-3 AES-GCM messaging | Default algorithm in web and CLI |
| FR-4 verified display | Receiver acknowledgement and decoded UI output |
| FR-5 tamper/replay rejection | Unit tests and real wire-level attack controls |
| FR-6 chunked files | Binary transfers verified through 100 MiB in controlled tests |
| FR-7 keys and session rotation | Encrypted signing identities; fresh ephemeral/session keys per connection |
| FR-8 simultaneous clients | Ten-client integration test; bounded public sessions |
| FR-9 event logging | Connection/failure/transfer events exclude keys and payload content |
| FR-10 algorithm choice | AES-256-GCM and ChaCha20-Poly1305 |
| FR-11 per-message signatures | Deferred; signatures currently authenticate the handshake |

## Evaluation

The Python suite passes 74 tests, with 100% crypto, 100% educational hashing, and 91% network line coverage. Eight browser workflows cover desktop/mobile messaging, account registration/private storage, byte visualizations, MD5/SHA-256 fingerprint comparisons, attacks, file handling, and benchmark charts. Containerized sender/receiver smoke testing and a two-user Docker transfer smoke test also pass.

In the recorded localhost run, median 1 KiB message round-trip times were 0.142 ms for AES-GCM and 0.156 ms for ChaCha20-Poly1305. Median verified 100 MiB transfer times were 559.877 ms and 602.619 ms respectively. See the raw benchmark artifact and methodology for scope and sample counts.

## Deployment and boundaries

Docker Compose provisions identities, isolates the TCP receiver, and serves the UI/API. An optional Caddy profile provides public HTTPS after domain/VPS configuration. Hosted endpoints can see demonstration plaintext; the project does not claim browser-to-browser end-to-end encryption. Keys and sessions are process-local; scaling requires an explicit connection/state ownership design.

Public hosting, Wireshark evidence, native Windows/macOS validation, and a matched plaintext throughput baseline are remaining evaluation tasks. The protocol is educational and has not received an independent security review. Full TLS integration and per-message key evolution remain future extensions.

## Reproduction

Use the root README for setup; `docs/protocol.md` for the wire format; `docs/test-report.md` for verification; and `docs/wireshark-guide.md` for plaintext/encrypted captures.
