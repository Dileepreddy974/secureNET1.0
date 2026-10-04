# SecureNet / Lab

**Private data. Public proof.** A brutalist, interactive computer-networking laboratory with a real Python TCP sender and receiver.

## What works

- Beginner-friendly MD5/SHA-256 fingerprint comparison: actual hash values, highlighted changes, bit-change counts, UTF-8 byte view, and a plain-language guide.
- AES-256-GCM and ChaCha20-Poly1305 authenticated messaging.
- Fresh X25519 session keys, Ed25519-signed handshakes, pinned endpoint identities, and HKDF-SHA256.
- Actual ciphertext/nonce/tag inspection, live events, and step-by-step encryption/decryption playback.
- Chunked binary file transfers with authenticated completion, SHA-256 comparison, and verified downloads.
- Real ciphertext modification, record replay, and handshake key-substitution demonstrations.
- Measured cipher benchmarks with CSV export, plus a localhost TCP benchmark script.
- Independent visitor sessions, CLI tools, tests, and container deployment with an HTTPS proxy profile.
- Multi-user accounts with Argon2id login, unique SecureNet IDs, encrypted Ed25519 identity storage, private file vaults, quotas, ownership checks, receiver lookup, user-to-user TCP transfers, transfer history, receipts, and private security events.
- Educational Caesar, Vigenère, XOR, RSA-OAEP, Ed25519, and ECC/X25519 demonstrations clearly marked for learning.

## Quick start: Docker

From this project directory, with Docker Compose installed:

```bash
docker compose up --build -d --wait
```

Open **http://localhost:8000**. Click **CONNECT**, enter a message, and choose **ENCRYPT + SEND**. Select a pipeline step or **REPLAY** to inspect the recorded transfer.

For the simplest introduction, open **HASHING** or **TRY MD5 + SHA-256**, click **CONNECT**, and compare `Hello` with `hello`. The two hash cards show how a one-letter change affects each fingerprint. Use **USE THE SAME TEXT** to see that identical input gives identical output.

**Simple terminology:** encryption locks data; decryption unlocks it; hashing makes a one-way fingerprint. MD5 and SHA-256 cannot decrypt messages. MD5 is a historical teaching example with known collision weaknesses; SHA-256 is the modern file-fingerprint choice. The message/file encryption still uses AES-GCM or ChaCha20-Poly1305.

For multi-user mode, open **ACCOUNT** and register two users. Each gets a permanent `SN-XXXX-XXXX` SecureNet ID. Log in as one user, open **SEND DATA**, enter the other user’s SecureNet ID, click **VERIFY RECEIVER**, choose a file, and click **SEND SECURELY**. The backend runs the existing authenticated TCP protocol with the two users’ Ed25519 identities, fresh X25519 keys, HKDF-SHA256, and AES-GCM or ChaCha20-Poly1305. The receiver’s encrypted file is committed only after chunk checks, SHA-256, and byte-for-byte comparison pass.

```bash
docker compose logs --follow web receiver
docker compose down
```

The first startup provisions encrypted identities in separate named volumes. The services run as a non-root user. Only the web port is published, on host loopback. Temporary demo files use bounded tmpfs mounts; keys persist across restarts.

## Local Python + frontend development

Requires Python 3.12+ and Node 20.19+ or 22+. This workspace was tested with Python 3.14 and Node 24; the container uses Python 3.13 and Node 22.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
npm --prefix frontend ci
npm --prefix frontend run build
securenet serve
```

Open **http://127.0.0.1:8000**. The default local mode starts a real TCP receiver on port 9000 inside the API process. Docker runs the receiver in a separate container.

On Windows, activate with `.venv\Scripts\Activate.ps1`. If Linux reports that `ensurepip` is unavailable, install the matching Python `venv` package before creating the environment. Stop the Docker stack before using the same web port locally.

For frontend hot reload, run `npm --prefix frontend run dev` in another terminal and use the Vite URL. Its `/api` proxy connects to the Python server.

## CLI demonstration

With the virtual environment activated:

```bash
securenet init
securenet receiver
```

In another terminal:

```bash
securenet send "Meet me on the other side."
securenet send "Try another cipher" --algorithm ChaCha20-Poly1305
securenet file ./sample.pdf ./verified.pdf
securenet benchmark
securenet hash "Hello" --compare "hello"
```

`file` performs a verified transfer to the receiver and retrieves a verified copy over the encrypted return channel. The output path must not already exist. The CLI prints plaintext only as an explicit user-facing result; event logs do not include it.

For two machines, securely provision only the appropriate role directory and unlock secret on each host. Run the receiver with `--host 0.0.0.0` and use `--host RECEIVER_LAN_IP` on the sender. See [the protocol guide](docs/protocol.md) for trust provisioning and rotation.

## Trust boundaries and limits

The browser controls **hosted Python endpoints**. Those endpoints see plaintext. HTTPS protects the public browser connection; the project protocol protects sender-to-receiver TCP records. This is an educational protocol, not a replacement for TLS.

- Secret session keys never appear in the UI or logs.
- Public keys, record headers, lengths, timing, and addresses remain observable.
- Each session owns its files and event stream. Public limit: 10 MiB per file, three files per session; CLI limit: 100 MiB.
- Sessions expire after 15 minutes without application activity or 30 minutes total. Expired files are removed by a 15-second cleanup sweep. One event stream per session is supported.
- At most 20 web sessions, 30 operations per minute per session, 12 new sessions per minute per address, and 40 new sessions per minute globally.
- Changing algorithms requires a new authenticated session. Interrupted transfers restart with fresh keys.
- The website’s record inspector shows actual application-record bytes. A separate Wireshark capture observes actual network packets.
- Benchmark results and event summaries are in memory; source payloads are not retained in a database.
- The Hashing exercise accepts up to 8 KiB per text, including empty text. It calculates both hashes on the Python web server, and does not send a TCP application message or write input to logs. HTTPS protects this browser request in deployment.
- Accounts use Argon2id password hashes, opaque seven-day sessions, CSRF tokens, and server-side ownership checks. Account private identity keys are encrypted with a separately mounted account master secret. Passwords, private keys, session secrets, and raw encryption keys are never returned or logged.
- Account files are encrypted at rest with per-file AES-256-GCM keys wrapped by the account master secret. Default account limits are 100 MiB per file, 100 files, and 10 GiB per user; configure `SECURENET_MAX_FILE_SIZE`, `SECURENET_MAX_FILES_PER_USER`, and `SECURENET_MAX_STORAGE_PER_USER`.
- User-to-user TCP transfers are hosted by the authenticated application process on loopback; their handshake transcript includes sender ID, receiver ID, and transfer ID. Demo endpoint/CLI mode remains available unchanged.

## Verification

```bash
python -m pytest --cov=securenet.crypto --cov=securenet.network --cov-report=term-missing --cov-fail-under=80
npm --prefix frontend run build
```

Browser tests (run from `frontend/`):

```bash
npx playwright install --with-deps chromium
npm test
```

Browser tests start an isolated API on port 8001 and receiver on 9001. Screenshots and failure traces are under `frontend/test-results/`.

```bash
python benchmarks/run.py --output docs/benchmark-results.json
```

See [test results](docs/test-report.md), [benchmark methodology](docs/benchmark-report.md), and [the Wireshark guide](docs/wireshark-guide.md).

See [the multi-user architecture guide](docs/multi-user.md) and [the repository audit](docs/repository-audit.md) for account/database/storage design, authorization rules, and transfer security details.

## Public deployment

Use a Linux VPS with approximately 2 vCPUs, **4 GB RAM recommended**, Docker, and a domain pointing to its address. Create a `.env` from the values in `.env.example`:

```dotenv
LAB_DOMAIN=lab.your-domain.com
SECURENET_HTTPS=1
SECURENET_PUBLIC_ORIGIN=https://lab.your-domain.com
```

Open inbound ports 80 and 443, then run:

```bash
docker compose --profile live up --build -d --wait
```

Caddy obtains and renews the website certificate. The receiver has no published port. Keep a single web worker: live session keys and TCP connections belong to that process. Reverse-proxy headers are trusted only in this private-proxy/loopback deployment topology.

To update, keep the key volumes and run the same build/start command; active sessions restart. To roll back, retag the previously saved application image as `securenet-lab:local` and run `docker compose --profile live up -d --force-recreate` without `--build`.

## Code map

```text
src/securenet/
  crypto.py       primitives, identity storage, directional records
  network.py      TCP framing, signed handshake, key confirmation
  receiver.py     message and file receiver
  client.py       shared sender, downloads, attack demonstrations
  api.py          visitor sessions, REST API, live SSE events
  benchmark.py    bounded primitive benchmark
  hashing.py      MD5/SHA-256 educational fingerprint comparison
  education.py    Caesar/Vigenère/XOR/RSA/Ed25519/ECC learning demos
  accounts.py     SQLite users, Argon2id, SecureNet IDs, files, transfers, events
  vault.py        streaming AES-GCM private file vault and byte comparison
  user_transfer.py authenticated account-to-account TCP transfers
  cli.py          terminal commands
frontend/src/     React/TypeScript dashboard and self-hosted fonts
tests/            cryptographic, protocol, file, and API tests
benchmarks/       reproducible measurement and plaintext-capture helpers
deploy/           container image and HTTPS configuration
docs/             protocol, evaluation, and capture instructions
```

Public hosting requires a VPS and domain configuration; the repository contains the deployable setup.
