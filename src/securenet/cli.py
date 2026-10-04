"""The same authenticated channel, accessible from a terminal."""

import asyncio
import json
import logging
import os
from pathlib import Path

import typer

from .benchmark import run_benchmark
from .client import receive_file, send_file, send_message
from .crypto import ALGORITHMS, initialize_identities, load_identity
from .hashing import compare_hashes
from .network import connect
from .receiver import CHUNK_SIZE, Receiver

app = typer.Typer(help="SecureNet encryption laboratory")


def paths():
    return (Path(os.getenv("SECURENET_KEYS_DIR", ".data/keys")),
            Path(os.getenv("SECURENET_PASSWORD_FILE", ".data/key-password")))


@app.command()
def init():
    """Generate encrypted endpoint identities and provision pinned peer keys."""
    initialize_identities(*paths())
    typer.echo("Endpoint identities initialized. Private keys stay on their respective endpoints.")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000):
    """Start the website/API and (by default) a local TCP receiver."""
    import uvicorn
    uvicorn.run("securenet.api:app", host=host, port=port, access_log=False,
                forwarded_allow_ips=os.getenv("SECURENET_TRUSTED_PROXIES", "127.0.0.1"))


@app.command()
def receiver(host: str = "127.0.0.1", port: int = 9000):
    """Run a standalone TCP receiver using previously initialized identities."""
    keys, password = paths()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    async def run():
        service = Receiver(load_identity(keys / "receiver/identity.pem", password),
                           (keys / "receiver/peer.pub").read_bytes(), Path(".data/received"))
        await service.start(host, port)
        typer.echo(f"Authenticated TCP receiver listening on {host}:{port}")
        try:
            await service.server.serve_forever()
        finally:
            await service.stop()
    asyncio.run(run())


@app.command()
def send(text: str, host: str = "127.0.0.1", port: int = 9000, algorithm: str = ALGORITHMS[0]):
    """Encrypt a message, send it over TCP, and print the verified receipt."""
    async def run():
        keys, password = paths()
        channel = await connect(host, port, load_identity(keys / "sender/identity.pem", password),
                                (keys / "sender/peer.pub").read_bytes(), algorithm)
        try:
            typer.echo(json.dumps(await send_message(channel, text), indent=2, ensure_ascii=False))
        finally:
            await channel.close()
    asyncio.run(run())


@app.command()
def file(path: Path, output: Path, host: str = "127.0.0.1", port: int = 9000,
         algorithm: str = ALGORITHMS[0]):
    """Transfer up to 100 MiB and save a verified copy returned by the receiver."""
    async def run():
        keys, password = paths()
        channel = await connect(host, port, load_identity(keys / "sender/identity.pem", password),
                                (keys / "sender/peer.pub").read_bytes(), algorithm)

        async def chunks():
            with path.open("rb") as source:
                while chunk := source.read(CHUNK_SIZE):
                    yield chunk
        try:
            result = await send_file(channel, path.name, path.stat().st_size, chunks())
            await receive_file(channel, result["id"], output, result["receiver_sha256"], result["size"])
            typer.echo(json.dumps(result, indent=2))
        finally:
            await channel.close()
    asyncio.run(run())


@app.command()
def benchmark():
    """Print measured AES-GCM/ChaCha20 benchmark results as JSON."""
    typer.echo(json.dumps(run_benchmark(), indent=2))


@app.command("hash")
def hash_text(text: str, compare: str | None = None):
    """Make MD5/SHA-256 fingerprints; optionally compare with changed text."""
    try:
        result = compare_hashes(text, text if compare is None else compare)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo("Hashing makes a one-way fingerprint. It cannot be decrypted.")
    for row in result["rows"]:
        typer.echo(f"{row['algorithm']} ({row['bits']} bits): {row['original']}")
        if compare is not None:
            typer.echo(f"  Changed text: {row['changed']}")
            typer.echo(f"  Bits changed: {row['changed_bits']} / {row['bits']}")
    typer.echo("MD5 is a historical learning example. Use SHA-256 for modern file fingerprints.")


if __name__ == "__main__":
    app()
