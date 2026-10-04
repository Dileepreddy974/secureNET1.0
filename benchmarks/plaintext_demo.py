"""A one-connection, loopback-only plaintext comparison for packet capture."""

import argparse
import socket

SAMPLE = b"SECURENET_PLAINTEXT_SAMPLE: Meet me on the other side.\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("receiver", "sender"))
    args = parser.parse_args()
    if args.role == "receiver":
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 9002))
            listener.listen(1)
            print("Loopback plaintext baseline waiting on port 9002")
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(10)
                payload = connection.makefile("rb").readline(4096)
                connection.sendall(payload)
                print("Sample received and echoed")
    else:
        with socket.create_connection(("127.0.0.1", 9002), timeout=10) as connection:
            connection.sendall(SAMPLE)
            reply = connection.makefile("rb").readline(4096)
            assert reply == SAMPLE
            print("Plaintext baseline round trip complete")


if __name__ == "__main__":
    main()
