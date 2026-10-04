# SecureNet protocol v1

## Architecture and trust

Browser → HTTPS reverse proxy → FastAPI/Python sender → encrypted TCP → Python receiver.

The local default binds TCP to 127.0.0.1:9000. Docker uses an isolated bridge network and separately mounted sender/receiver identity volumes. The website exposes demonstration plaintext to its owning visitor; hosted endpoints necessarily handle that plaintext too. Cross-visitor file access is rejected.

## Identity provisioning

`securenet init` creates independent Ed25519 signing keys and encrypted PKCS8 PEM files, plus a pinned peer public key in each role directory. Existing keys are preserved. If the saved peer key differs from the locally provisioned identity, initialization fails rather than silently accepting a replacement.

For a two-machine lab, initialize in a trusted setup environment, transfer each role's `identity.pem` and `peer.pub` via a trusted channel to its respective host, and securely provide its unlock secret. The demonstration initializer uses one generated secret to unlock both roles; each host receives only its own private key. Public-key fingerprints are SHA-256 of the raw 32-byte identity public key. Verify fingerprints out of band.

To rotate identity keys, stop the endpoints and provision a new pair in a new directory. Verify and distribute the new pins before restarting. Ephemeral keys are independently rotated on every connection. Private-key files have mode 0600 on POSIX; the default local unlock secret is another mode-0600 file, so file encryption does not defend against an attacker with access to both. Deployment mounts the secret separately. Python does not guarantee zeroization of all memory copies.

## Framing

Every TCP frame begins with an unsigned four-byte big-endian length. Handshake frames are bounded at 8192 bytes; protected records at 128 KiB. The reader uses exact-length reads and handles both fragmentation and coalescing.

The handshake has 20-second read/write limits. Established receiver connections allow a 15-minute idle wait for the next header, while partially delivered bodies retain a 20-second timeout. Client replies time out after 20 seconds.

## Handshake

1. Sender sends canonical JSON: protocol version, chosen algorithm, Ed25519 public identity, fresh X25519 ephemeral public key, and fresh 32-byte challenge.
2. Receiver checks version, allowed algorithm, and pinned sender identity. It generates its own ephemeral key and challenge.
3. Receiver sends its hello and Ed25519 signature of `receiver:` plus the canonical transcript.
4. Sender checks the pinned receiver identity, algorithm equality, and signature. It signs `sender:` plus the same transcript.
5. Receiver verifies the sender signature.
6. Both derive the X25519 shared secret locally. The transcript includes both complete hellos under role-labeled fields and `protocol: securenet/v1`.
7. HKDF-SHA256 uses the transcript SHA-256 as salt and a protocol-specific info string to derive 72 bytes: two 32-byte keys and two four-byte nonce prefixes.
8. Both exchange encrypted `finished` records. Application data is accepted only after successful confirmation.

Public handshake parameters and signatures are visible. Private and derived secret keys are never transmitted. Fresh ephemeral X25519 material provides session-level forward secrecy under the protocol assumptions; there is no per-message ratchet.

## Protected records

```text
4-byte frame length
  1-byte type       (1 = JSON application message, 2 = binary file chunk)
  8-byte sequence   (unsigned, big-endian)
  4-byte AEAD length
  ciphertext
  16-byte authentication tag
```

Nonce = four-byte directional prefix || eight-byte sequence number.

Associated data = transcript hash || direction label (`s2r` or `r2s`) || the 13-byte record header.

Each direction has independent key/nonce state and a strictly increasing counter, including key-confirmation records. Receive state advances only after successful AEAD verification. Unknown types, incorrect lengths, duplicate/out-of-order counters, and invalid tags are rejected. Connections must rekey before one million records. Reconnects always establish new keys.

Application JSON supports message/acknowledgement, file begin/ready/end/acknowledgement, download begin/end, and error codes. Receivers release messages only after authentication. A detected protocol violation closes that connection, with a protected error response when possible.

## Files

The encrypted begin record carries display filename and total size. Binary chunks are at most 64 KiB, individually authenticated and ordered. The final encrypted manifest includes the source SHA-256. The receiver checks total byte count and independently computed hash before acknowledging completion.

Missing final manifests, changed chunks, short files, and extra data cannot produce a successful acknowledgement. Generated temporary paths ignore client-provided directory names. Partial and completed files are removed at connection cleanup. Downloaded copies are verified again and stored under generated names for session-authorized access. Existing CLI output files are never overwritten or deleted.

## Visualization fidelity

The API reports real wire bytes, nonce, sequence, tag, public fingerprints, and operation timing. Ciphertext display is truncated at 512 bytes. The JSON envelope is encrypted along with the user's message, so ciphertext length exceeds the UTF-8 text length.

SSE events carry stage and count metadata, not secret keys or user message content. Message content travels only through the owning session's explicit API response. Playback reorganizes the recorded result into conceptual steps; authenticated decryption is an atomic library operation, not a separate unauthenticated plaintext release.

### Beginner hashing exercise

`POST /api/hashes` calculates MD5 and SHA-256 on two UTF-8 texts using Python `hashlib`. Each input is bounded to 8192 encoded bytes. No whitespace, case, or Unicode normalization is applied. Hashes have fixed lengths (MD5: 128 bits / 32 hex characters; SHA-256: 256 bits / 64 hex characters). The highlighted character differences and the XOR bit count are calculated from the real digests.

The endpoint requires the existing session/CSRF protections and rate limits. Input remains in request memory, is not logged, and is not transmitted through the lab's TCP protocol. SSE reports only the byte counts. This teaching endpoint has no effect on channel keys, AEAD, or file authentication. MD5 is marked as a historical, collision-broken example and invoked with `usedforsecurity=False`; no security decision relies on its output. Hashes are one-way and do not replace encryption or authenticated integrity checks.

## Threat handling

| Threat | Implementation |
|---|---|
| Passive observation | AEAD on all application records |
| MITM during key exchange | Pre-provisioned peer pins, role-labeled signed transcript, key confirmation |
| Tampering | AEAD validates ciphertext and authenticated header |
| Replay / reordering | Strict directional counters and session-bound associated data |
| Nonce reuse | Directional keys, monotonic counters, fresh handshake on reconnect |
| Resource exhaustion | Bounded frames, reads, files, sessions, operations, and public benchmark frequency |
| Cross-visitor access | Opaque HttpOnly session cookie; ownership checks on files and event streams |
| Browser request forgery | Same-origin checking, SameSite cookies, per-session CSRF tokens |

Endpoint compromise, host administrator access, traffic analysis, and a formal proof of the custom protocol remain outside the lab's guarantees.
