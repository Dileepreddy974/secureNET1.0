# Verification report

Date: 2026-10-04. Environment: Linux / WSL2 x86_64, Python 3.14.4, cryptography 47.0.0, Node 24.21.0. Container runtime: Python 3.13. Browser: Playwright Chromium.

## Results

| Check | Result |
|---|---|
| Python unit/integration/API suite | **74 passed** |
| Full `securenet` line coverage | **83%** |
| Crypto module line coverage | **100%** |
| Network module line coverage | **91%** |
| Combined crypto/network coverage | **94.72%** |
| Educational hashing module coverage | **100%** |
| Combined crypto/network/hashing coverage | **94.96%** |
| TypeScript check and Vite production build | Passed |
| Desktop browser workflows, 4 workflows, 1440 × 1000 | 4 passed |
| Mobile browser workflows, 4 workflows, 390 × 844 | 4 passed |
| Docker Compose build/start and health check | Passed |
| Separate-container functional smoke test | Passed |
| Two-user Docker account transfer smoke test | Passed |

## Tested behavior

- Both algorithms: empty, ASCII, Unicode, and binary round trips.
- Wrong key, wrong nonce, altered associated data, changed ciphertext/tag, invalid header, replay, ordering, and cross-session rejection.
- Directional-key separation, fresh session keys, 1,000 distinct consecutive nonces, counter exhaustion, and record-size limits.
- Encrypted identity storage, POSIX file permissions, idempotent initialization, pin mismatch, and invalid private-key types.
- Fragmented and combined TCP reads, EOF, timeout, malformed JSON, unsupported algorithms, untrusted identities, altered handshakes, and a real interception proxy.
- Ten simultaneous authenticated clients and concurrent sends on one channel.
- Files of 0 B, 1 KiB, 65,537 B, 1 MiB, and **100 MiB**, using both algorithms. Independent source/receiver/download hashes match.
- Existing CLI output preservation, dropped transfers, incomplete files, wrong final hashes, and temporary-file cleanup.
- Event logs omit plaintext and session keys.
- Web session ownership, CSRF/origin rejection, request/file quotas, algorithm rotation, and reconnection after session expiration.
- Browser messaging, live SSE, UTF-8 byte evidence, step playback, all three attacks, file selection/download, benchmark results, and desktop/mobile overflow checks.
- Production security policy generated no browser CSP errors in the messaging workflow.
- MD5/SHA-256 known vectors, empty text, unchanged inputs, Unicode bytes, exact bit-difference counts, and both input-size boundaries.
- Authenticated hashing API, CSRF rejection, no input logging, and rejection of MD5 as a network encryption algorithm.
- Multi-user registration/login/logout, Argon2id password hashing, unique SecureNet IDs, protected public identity fingerprints, private encrypted-at-rest storage, quotas, receiver lookup, transfer history, receipts, security events, and file tamper simulation.
- Two-user IDOR protection: a sender cannot download/delete another user’s file; received files are available only to their owner; transfer history/events are participant-scoped.
- Real user-to-user loopback TCP transfer with per-user Ed25519 identities, context-bound X25519/HKDF handshake, ChaCha20-Poly1305, chunk hashes, whole-file SHA-256, byte comparison, encrypted sender/receiver vault commits, and verified download.
- Classical/RSA/Ed25519/ECC educational API demonstrations.
- Desktop/mobile hashing flow, preserved text when connecting, byte visualization, highlighted differences, stale-result clearing, and identical-input comparison.
- CLI `securenet hash abc --compare abd` produces the expected MD5/SHA-256 fingerprints and bit-change counts.

The Docker smoke test used actual HTTP requests against port 8000 and a receiver in a separate container. It verified the website, signed handshake, message receipt, binary upload/hash/download, all attack demonstrations, and session cleanup. The account smoke test additionally registered two users, performed a real AES-GCM account transfer, downloaded the receiver-owned encrypted file, and verified the receipt’s byte count and `VERIFIED` status.

## Commands

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest --cov=securenet --cov-report=term-missing -q
npm --prefix frontend run build
LD_LIBRARY_PATH=/tmp/omnirush/browser-libs/usr/lib/x86_64-linux-gnu npm --prefix frontend test
docker compose up --build -d --wait
```

Run the frontend test after installing Chromium and its runtime libraries with `npx playwright install --with-deps chromium`. On this environment, three missing browser libraries were extracted into a temporary directory without administrator access; the passing browser command used `LD_LIBRARY_PATH=/tmp/omnirush/browser-libs/usr/lib/x86_64-linux-gnu npm --prefix frontend test`.

Playwright saves initial and verified screenshots under `frontend/test-results/`. Successful test traces are discarded; failure traces are retained.

## Remaining evaluation work

- Public DNS/HTTPS deployment and external-internet evaluation require hosting access and a domain.
- Wireshark captures and screenshots should be generated using the supplied guide and fixed plaintext helper.
- Native Windows/macOS execution has not been exercised in this environment.
- The <10% encryption-overhead goal needs a matched timed plaintext baseline; it is not claimed as achieved.
- Tests demonstrate rejection for the exercised attacks; they do not constitute a formal security proof of the educational protocol.
- The production UI account test uses DOM event dispatch for a sidebar action because the brutalist full-page scroll layout can put the sidebar action under content during automated pointer scrolling; the action handler and backend account workflow are still exercised.
