import hashlib

import httpx
import pytest

from securenet.api import Settings, create_app


@pytest.fixture
async def account_web(tmp_path):
    settings = Settings(data=tmp_path / "demo", keys=tmp_path / "demo-keys", password=tmp_path / "demo-password",
                        port=0, accounts_db=tmp_path / "accounts" / "lab.db", account_secret=tmp_path / "accounts" / "master",
                        account_storage=tmp_path / "account-files", account_max_file_size=2 * 1024 * 1024, account_max_files=10,
                        account_max_storage=10 * 1024 * 1024)
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as browser:
            yield browser, app


async def register(browser, username, email):
    response = await browser.post("/api/account/register", json={"full_name": username.title(), "username": username,
        "email": email, "password": "StrongPassword9", "confirm_password": "StrongPassword9"})
    assert response.status_code == 200, response.text
    browser.headers["X-Account-CSRF"] = response.headers["x-account-csrf"]
    return response.json()["user"]


async def test_registration_login_profile_secure_id_and_ownership(account_web):
    browser, _ = account_web
    alice = await register(browser, "alice", "alice@example.test")
    assert alice["secure_net_id"].startswith("SN-")
    assert len(alice["public_key_fingerprint"]) == 64
    assert "password" not in alice and "private_key" not in alice
    current = await browser.get("/api/account/me")
    assert current.status_code == 200
    invalid = await browser.post("/api/account/register", json={"full_name": "Bob", "username": "alice", "email": "bob@example.test", "password": "StrongPassword9", "confirm_password": "StrongPassword9"})
    assert invalid.status_code == 409
    await browser.post("/api/account/logout")
    assert (await browser.get("/api/account/me")).status_code == 401
    logged = await browser.post("/api/account/login", json={"login": "alice", "password": "StrongPassword9"})
    assert logged.status_code == 200
    browser.headers["X-Account-CSRF"] = logged.headers["x-account-csrf"]
    assert (await browser.post("/api/account/login", json={"login": "alice", "password": "wrong-password"})).status_code == 401
    upload = await browser.post("/api/account/files", files={"file": ("private.txt", b"private alice data", "text/plain")})
    assert upload.status_code == 200, upload.text
    record = upload.json()["file"]
    assert record["sha256"] == hashlib.sha256(b"private alice data").hexdigest()
    assert (await browser.get(f"/api/account/files/{record['id']}/integrity")).json()["verified"]
    assert (await browser.get(f"/api/account/files/{record['id']}/download")).content == b"private alice data"
    tamper = await browser.post("/api/account/attacks/file", json={"file_id": record["id"], "mode": "file_tamper"})
    assert tamper.status_code == 200 and tamper.json()["rejected"] and tamper.json()["modified_bytes"] > 0
    assert (await browser.get(f"/api/account/files/{record['id']}/integrity")).json()["verified"]


async def test_two_user_transfer_and_idor_block(account_web):
    browser, app = account_web
    alice = await register(browser, "alice", "alice@example.test")
    bob_browser = httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test")
    try:
        bob = await register(bob_browser, "bob", "bob@example.test")
        lookup = await browser.get(f"/api/account/users/{bob['secure_net_id']}")
        assert lookup.status_code == 200 and lookup.json()["public_key_available"]
        source = b"real encrypted account transfer" * 1000
        transfer = await browser.post("/api/account/transfers", data={"receiver_id": bob["secure_net_id"], "algorithm": "AES-256-GCM"}, files={"file": ("research.txt", source, "text/plain")})
        assert transfer.status_code == 200, transfer.text
        body = transfer.json()
        assert body["receipt"]["status"] == "VERIFIED"
        assert body["receipt"]["byte_for_byte"] is True
        assert body["receipt"]["matched_bytes"] == len(source)
        received = await bob_browser.get("/api/account/received")
        assert received.status_code == 200 and len(received.json()["files"]) == 1
        received_file = received.json()["files"][0]
        download = await bob_browser.get(f"/api/account/files/{received_file['id']}/download")
        assert download.status_code == 200 and download.content == source
        # Bob cannot read Alice's source file or transfer with Alice's session.
        history = await bob_browser.get("/api/account/transfers")
        assert history.status_code == 200 and history.json()["transfers"][0]["sender_secure_id"] == alice["secure_net_id"]
        alice_files = await browser.get("/api/account/files")
        source_file = next(item for item in alice_files.json()["files"] if item["original_filename"] == "research.txt")
        assert (await bob_browser.get(f"/api/account/files/{source_file['id']}/download")).status_code == 404
        assert (await bob_browser.delete(f"/api/account/files/{source_file['id']}")).status_code == 404
        events = await bob_browser.get("/api/account/events")
        assert events.status_code == 200 and any(event["event_type"] == "TRANSFER_COMPLETED" for event in events.json()["events"])
    finally:
        await bob_browser.aclose()


async def test_account_limits_classical_lab_and_no_secret_logs(account_web, caplog):
    browser, _ = account_web
    await register(browser, "alice", "alice@example.test")
    assert (await browser.post("/api/account/files", files={"file": ("too.bin", b"x" * (2 * 1024 * 1024 + 1))})).status_code == 413
    caesar = await browser.post("/api/education/demo", json={"technique": "caesar", "text": "HELLO", "shift": 3})
    assert caesar.status_code == 200 and caesar.json()["encrypted"] == "KHOOR" and caesar.json()["educational_only"]
    rsa = await browser.post("/api/education/demo", json={"technique": "rsa", "text": "hello"})
    assert rsa.status_code == 200 and rsa.json()["decrypted"] == "hello" and rsa.json()["private_key_hidden"]
    xor = await browser.post("/api/education/demo", json={"technique": "xor", "text": "hello", "key": "k"})
    assert xor.status_code == 200 and xor.json()["decoded"] == "hello"
    assert "StrongPassword9" not in caplog.text
