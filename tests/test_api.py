import hashlib
import asyncio

import httpx
import pytest

from securenet.api import Settings, create_app


@pytest.fixture
async def web(tmp_path):
    settings = Settings(data=tmp_path / "data", keys=tmp_path / "keys", password=tmp_path / "password", port=0)
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as browser:
            yield browser, app


async def login(browser):
    response = await browser.post("/api/session", json={"algorithm": "AES-256-GCM"})
    assert response.status_code == 200, response.text
    browser.headers["X-CSRF-Token"] = response.json()["csrf"]
    return response.json()


async def test_full_web_workflow(web):
    browser, _ = web
    assert (await browser.get("/api/health")).status_code == 200
    await login(browser)
    result = await browser.post("/api/messages", json={"text": "hello browser 🔒"})
    assert result.status_code == 200 and result.json()["text"] == "hello browser 🔒"
    content = b"binary\x00\xffdata" * 10000
    transfer = await browser.put("/api/files?name=test.bin", content=content)
    assert transfer.status_code == 200, transfer.text
    body = transfer.json()
    assert body["source_sha256"] == body["receiver_sha256"] == hashlib.sha256(content).hexdigest()
    downloaded = await browser.get(f"/api/files/{body['download_id']}")
    assert downloaded.content == content
    assert downloaded.headers["x-content-type-options"] == "nosniff"
    for mode in ("tamper", "replay", "handshake"):
        response = await browser.post("/api/attacks", json={"mode": mode})
        assert response.status_code == 200, response.text
        assert response.json()["rejected"]
    assert (await browser.post("/api/messages", json={"text": "main session still works"})).status_code == 200
    assert (await browser.delete("/api/session")).status_code == 200
    assert (await browser.get(f"/api/files/{body['download_id']}")).status_code == 401


async def test_session_ownership_csrf_and_origin(web):
    browser, app = web
    await login(browser)
    upload = (await browser.put("/api/files?name=a.txt", content=b"only mine")).json()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as other:
        assert (await other.get(f"/api/files/{upload['download_id']}")).status_code == 401
        await login(other)
        assert (await other.get(f"/api/files/{upload['download_id']}")).status_code == 404
        assert (await other.post("/api/messages", json={"text": "b"}, headers={"X-CSRF-Token": "bad"})).status_code == 403
        assert (await other.post("/api/messages", json={"text": "b"}, headers={"Origin": "https://evil.example"})).status_code == 403
        assert (await other.post("/api/session", json={}, headers={"X-CSRF-Token": "bad"})).status_code == 403


async def test_api_limits_rotation_and_benchmarks(web):
    browser, _ = web
    assert (await browser.post("/api/session", json={"algorithm": "3DES"})).status_code == 422
    first = await login(browser)
    second = await browser.post("/api/session", json={"algorithm": "ChaCha20-Poly1305"})
    assert second.status_code == 200
    assert second.json()["handshake"]["sender_public"] != first["handshake"]["sender_public"]
    browser.headers["X-CSRF-Token"] = second.json()["csrf"]
    assert (await browser.post("/api/messages", json={"text": ""})).status_code == 422
    assert (await browser.post("/api/messages", json={"text": "a" * 140000})).status_code == 413
    escaped = "\x00" * 16384
    response = await browser.post("/api/messages", json={"text": escaped})
    assert response.status_code == 200 and response.json()["text"] == escaped
    assert (await browser.put("/api/files", content=b"x", headers={"Content-Length": str(11 * 1024 * 1024)})).status_code == 413
    for i in range(3):
        assert (await browser.put(f"/api/files?name={i}.txt", content=b"")).status_code == 200
    assert (await browser.put("/api/files", content=b"")).status_code == 413
    result = await browser.post("/api/benchmarks", json={})
    assert result.status_code == 200
    assert len(result.json()["rows"]) == 6
    assert all(row["throughput_mbps"] > 0 for row in result.json()["rows"])


async def test_expired_session_can_reconnect_without_old_csrf(web):
    browser, app = web
    await login(browser)
    app.state.settings.idle_seconds = .01
    await asyncio.sleep(.02)
    assert (await browser.get("/api/session")).status_code == 401
    del browser.headers["X-CSRF-Token"]
    response = await browser.post("/api/session", json={})
    assert response.status_code == 200


async def test_hash_lab_authentication_vectors_and_byte_limits(web, caplog):
    browser, _ = web
    payload = {"original": "abc", "changed": "abd"}
    assert (await browser.post("/api/hashes", json=payload)).status_code == 401
    await login(browser)
    assert (await browser.post("/api/hashes", json=payload, headers={"X-CSRF-Token": "wrong"})).status_code == 403
    response = await browser.post("/api/hashes", json=payload)
    assert response.status_code == 200
    assert response.json()["rows"][0]["original"] == "900150983cd24fb0d6963f7d28e17f72"
    assert response.headers["cache-control"] == "no-store"
    assert (await browser.post("/api/hashes", json={"original": "", "changed": ""})).status_code == 200
    assert (await browser.post("/api/hashes", json={"original": "", "changed": "🔒" * 2049})).status_code == 413
    assert (await browser.post("/api/hashes", json={"original": "x" * 8193, "changed": ""})).status_code == 422
    sentinel = "hash-input-should-not-be-logged"
    await browser.post("/api/hashes", json={"original": sentinel, "changed": sentinel})
    assert sentinel not in caplog.text
    # Hash algorithms never become selectable encryption ciphers.
    assert (await browser.post("/api/session", json={"algorithm": "MD5"})).status_code == 422
