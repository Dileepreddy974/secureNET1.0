import pytest

from securenet.crypto import initialize_identities, load_identity
from securenet.network import connect
from securenet.receiver import Receiver


@pytest.fixture
def identities(tmp_path):
    keys, password = tmp_path / "keys", tmp_path / "password"
    initialize_identities(keys, password)
    return {
        "keys": keys, "password": password,
        "sender": load_identity(keys / "sender/identity.pem", password),
        "receiver": load_identity(keys / "receiver/identity.pem", password),
        "sender_pin": (keys / "sender/peer.pub").read_bytes(),
        "receiver_pin": (keys / "receiver/peer.pub").read_bytes(),
    }


@pytest.fixture
async def endpoint(identities, tmp_path):
    server = Receiver(identities["receiver"], identities["receiver_pin"], tmp_path / "received")
    port = await server.start(port=0)
    channels = []

    async def open_channel(algorithm="AES-256-GCM"):
        channel = await connect("127.0.0.1", port, identities["sender"], identities["sender_pin"], algorithm)
        channels.append(channel)
        return channel

    yield server, port, open_channel
    for channel in channels:
        await channel.close()
    await server.stop()
