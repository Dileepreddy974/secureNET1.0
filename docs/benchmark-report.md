# Benchmark methodology

Run `python benchmarks/run.py --output docs/benchmark-results.json` from an activated project environment.

## Recorded localhost results — 2026-10-03

Source: [benchmark-results.json](benchmark-results.json). Linux/WSL2 x86_64, Python 3.14.4, cryptography 47.0.0.

| Measurement | AES-256-GCM | ChaCha20-Poly1305 |
|---|---:|---:|
| 1 KiB message median TCP round trip | 0.142 ms | 0.156 ms |
| 1 KiB message p95 TCP round trip | 0.200 ms | 0.323 ms |
| 1 MiB file median transfer | 6.778 ms | 8.087 ms |
| 100 MiB file median transfer | 559.877 ms | 602.619 ms |
| 100 MiB file median throughput | 178.61 MiB/s | 165.94 MiB/s |
| 1 MiB primitive encryption throughput | 930.82 MiB/s | 741.05 MiB/s |

All benchmark file hashes matched. The localhost message-latency target was met in this run. These results do not predict LAN/WAN performance or establish the file-overhead target.

## Cipher comparison

AES-256-GCM and ChaCha20-Poly1305 are measured with 1 KiB, 64 KiB, and 1 MiB payloads. Each pair uses five warm-up iterations and forty measured iterations. Encryption and decryption are timed separately with `perf_counter_ns`. Every result is decrypted and compared with the source. A new nonce is used each time under each key.

Reported fields: median encrypt/decrypt milliseconds, p95 encrypt milliseconds, and MiB/s derived from median encryption duration. These are in-memory primitive measurements, not end-to-end network bandwidth.

## TCP comparison

Each algorithm establishes an authenticated localhost TCP connection. Handshake duration is recorded separately. One hundred 1 KiB message round trips are measured after five warm-up messages. Files of 1 KiB, 1 MiB, and 100 MiB are transferred three times per algorithm using fresh sessions.

File measurements include source hashing, record encryption, TCP transport, receiver authentication, receiver temporary-file writes/hashing, and the verified acknowledgement. They exclude handshake and the optional return/download transfer. Each source/receiver hash pair must match.

## Interpretation

The generated JSON records Python, cryptography, OpenSSL, OS, architecture, timing samples, and actual results. Hardware load and virtualization affect results. Public-demo primitive results are cached for sixty seconds to limit repeated work.

The PRD's <100 ms message latency can be evaluated against the recorded localhost median/p95. LAN and internet results require measurements in those environments. The <10% file-encryption-overhead target requires an equivalent timed plaintext transfer baseline and has **not** been established by this report. The plaintext capture helper is for visual comparison, not a throughput baseline.
