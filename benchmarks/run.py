"""Measure primitives and real localhost TCP sessions. Run from the project root."""

import argparse
import asyncio
import json
import platform
import ssl
import statistics
import tempfile
import time
from pathlib import Path

from securenet.benchmark import run_benchmark
from securenet.client import send_file, send_message
from securenet.crypto import ALGORITHMS, initialize_identities, load_identity
from securenet.network import connect
from securenet.receiver import CHUNK_SIZE, Receiver


async def measure():
    report = run_benchmark()
    report["openssl"] = ssl.OPENSSL_VERSION
    report["os_release"] = platform.release()
    report["network"] = []
    with tempfile.TemporaryDirectory(prefix="securenet-benchmark-") as temporary:
        root = Path(temporary)
        keys, password = root / "keys", root / "password"
        initialize_identities(keys, password)
        sender = load_identity(keys / "sender/identity.pem", password)
        receiver = Receiver(load_identity(keys / "receiver/identity.pem", password),
                            (keys / "receiver/peer.pub").read_bytes(), root / "received")
        peer = (keys / "sender/peer.pub").read_bytes()
        port = await receiver.start(port=0)
        try:
            for algorithm in ALGORITHMS:
                channel = await connect("127.0.0.1", port, sender, peer, algorithm)
                handshake_ms = channel.handshake["duration_ms"]
                latency = []
                for i in range(105):
                    receipt = await send_message(channel, "x" * 1024)
                    if i >= 5:
                        latency.append(receipt["round_trip_ms"])
                await channel.close()
                entry = {"algorithm": algorithm, "handshake_ms": handshake_ms,
                         "message_size": 1024, "message_samples": 100,
                         "median_rtt_ms": statistics.median(latency),
                         "p95_rtt_ms": sorted(latency)[94], "files": []}
                content = bytes(range(256)) * 256
                for size in (1024, 1024 * 1024, 100 * 1024 * 1024):
                    runs = []
                    for _ in range(3):
                        channel = await connect("127.0.0.1", port, sender, peer, algorithm)

                        async def chunks():
                            for offset in range(0, size, CHUNK_SIZE):
                                yield content[:min(CHUNK_SIZE, size - offset)]
                        try:
                            result = await send_file(channel, "benchmark.bin", size, chunks())
                            runs.append(result)
                        finally:
                            await channel.close()
                    entry["files"].append({"size": size, "runs": 3,
                        "median_transfer_ms": statistics.median(r["duration_ms"] for r in runs),
                        "median_throughput_mib_s": statistics.median(r["throughput_mbps"] for r in runs),
                        "hashes_verified": all(r["source_sha256"] == r["receiver_sha256"] for r in runs)})
                report["network"].append(entry)
        finally:
            await receiver.stop()
    report["network_scope"] = "Localhost TCP; includes file hashing, receiver disk writes, and verified acknowledgement; excludes handshake from transfer timings. No plaintext overhead baseline measured."
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(asyncio.run(measure()), indent=2)
    if args.output:
        args.output.write_text(result + "\n")
        print(f"Measured benchmark report saved to {args.output}")
    else:
        print(result)
