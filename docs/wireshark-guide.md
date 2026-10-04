# Packet-capture lab

Use the fixed sample text below so captures contain only lab data. The record inspector in the UI is a view of serialized records, not a Wireshark capture.

## Before: plaintext

1. Open Wireshark and start capturing on the loopback interface (`lo` on Linux, loopback capture adapter on Windows, `lo0` on macOS).
2. In one terminal, from the project root:

   ```bash
   python benchmarks/plaintext_demo.py receiver
   ```

3. In another terminal:

   ```bash
   python benchmarks/plaintext_demo.py sender
   ```

4. Filter with `tcp.port == 9002`. Select a data packet and **Follow → TCP Stream**.
5. Confirm the visible marker `SECURENET_PLAINTEXT_SAMPLE` and readable sentence. Save the capture and an annotated screenshot.

The helper binds only to loopback, uses a fixed sample, and exits after one connection.

## After: encrypted

1. Start a fresh capture.
2. Run `securenet init`, then `securenet receiver`.
3. In another terminal:

   ```bash
   securenet send "SECURENET_PLAINTEXT_SAMPLE: Meet me on the other side."
   ```

4. Filter with `tcp.port == 9000` and follow the stream.
5. Inspect the public handshake, followed by binary application records. Search for the known marker: it must not appear in the encrypted application payloads. Confirm the CLI receipt contains the verified original text.
6. Save the capture and screenshot. Repeat with `--algorithm ChaCha20-Poly1305`.

Frames still reveal public keys, lengths, sequence metadata, IP addresses, and timing. The goal is absence of the sample message/file contents, not an absence of all recognizable protocol structure.

## Docker / VPS

Capturing browser port 443 primarily demonstrates HTTPS. To examine the project's TCP records, capture the private sender/receiver connection on port 9000 from the Docker host or receiver network namespace, then open that capture in Wireshark.

Example on a Linux Docker host with `tcpdump` installed:

```bash
sudo tcpdump -i any -s 0 -w encrypted-demo.pcap 'tcp port 9000'
```

Start a dedicated demo session, send the fixed sample, stop the capture, and inspect it. Host/container interfaces differ under Docker Desktop; the native CLI loopback procedure is the simplest reproducible alternative.

Actual Wireshark screenshots require capturing and inspecting this traffic. They are not fabricated by the website.
