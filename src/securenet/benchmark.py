"""Reproducible primitive benchmarks, distinct from network round-trip metrics."""

import os
import platform
import statistics
import time

import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def run_benchmark(iterations=40):
    rows = []
    for size in (1024, 64 * 1024, 1024 * 1024):
        payload = os.urandom(size)
        for name, factory in (("AES-256-GCM", AESGCM), ("ChaCha20-Poly1305", ChaCha20Poly1305)):
            cipher = factory(os.urandom(32))
            encrypt, decrypt = [], []
            for index in range(iterations + 5):
                nonce = index.to_bytes(12, "big")
                start = time.perf_counter_ns()
                encrypted = cipher.encrypt(nonce, payload, b"benchmark/v1")
                middle = time.perf_counter_ns()
                clear = cipher.decrypt(nonce, encrypted, b"benchmark/v1")
                end = time.perf_counter_ns()
                assert clear == payload
                if index >= 5:
                    encrypt.append((middle - start) / 1e6)
                    decrypt.append((end - middle) / 1e6)
            median = statistics.median(encrypt)
            rows.append({"algorithm": name, "size": size, "iterations": iterations,
                         "encrypt_ms": round(median, 5),
                         "decrypt_ms": round(statistics.median(decrypt), 5),
                         "p95_encrypt_ms": round(sorted(encrypt)[int(len(encrypt) * .95) - 1], 5),
                         "throughput_mbps": round(size / 1024 / 1024 / (median / 1000), 2)})
    return {"rows": rows, "python": platform.python_version(), "platform": platform.system(),
            "machine": platform.machine(), "cryptography": cryptography.__version__,
            "scope": "In-memory AEAD operations; excludes TCP, handshake, disk, and browser latency.",
            "warmup": 5, "timestamp": time.time()}
