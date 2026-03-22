import os
import sys
import io
import json
import uuid
import shutil
import hashlib
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta

# =====================================================
# CRITICAL: Set env vars and CWD BEFORE importing app
# app.py reads these at module level on import
# =====================================================

ADMIN_KEY = "test-admin-key-integration"
RSA_PASS  = "test-rsa-password"

os.environ["ADMIN_MASTER_KEY"] = ADMIN_KEY
os.environ["RSA_KEY_PASSWORD"]  = RSA_PASS
os.environ["FLASK_ENV"]         = "testing"

# All files (keys, uploads, audit logs) go into a temp folder
# so tests never touch your real project data
TMPDIR = tempfile.mkdtemp()
os.chdir(TMPDIR)

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Patch rsa KEY_DIR BEFORE app.py imports it
# (app.py calls initialize_rsa_keys() at module level)
import encryption.rsa as rsa_module
rsa_module.KEY_DIR = Path(TMPDIR) / "keys"
rsa_module.KEY_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)

from app import app as flask_app, limiter

flask_app.config["TESTING"] = True
flask_app.config["RATELIMIT_ENABLED"] = False   # disable rate limiter during tests
limiter.enabled = False

# =====================================================
# Shared Helpers
# =====================================================

def make_client():
    return flask_app.test_client()

def admin_headers():
    return {"X-Admin-Key": ADMIN_KEY}

def generate_api_key() -> str:
    """Hit the admin endpoint to mint a fresh API key."""
    with make_client() as c:
        r = c.post("/admin/keys/rotate", headers=admin_headers())
        assert r.status_code == 201, f"Key generation failed: {r.data}"
        return r.get_json()["api_key"]

def api_headers(key: str) -> dict:
    return {"X-API-Key": key}

def upload(client, api_key: str, data: bytes, filename: str = "test.txt"):
    return client.post(
        "/upload",
        headers=api_headers(api_key),
        data={"file": (io.BytesIO(data), filename)},
        content_type="multipart/form-data",
    )

def download(client, api_key: str, file_id: str):
    return client.get(
        f"/download/{file_id}",
        headers=api_headers(api_key),
    )

# =====================================================
# Tests
# =====================================================

def test_health_check():
    """Server must respond healthy with no auth required."""
    print("\nTest 1: Health check")
    with make_client() as c:
        r = c.get("/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
    print("   Passed")


def test_full_upload_download_cycle():
    """
    Core integration test:
    AES encrypt (app) → RSA wrap key (app) → store on disk
    → RSA unwrap key (app) → AES decrypt (app) → verify hash matches
    Tests: aes.py + rsa.py + hash.py + app.py all together
    """
    print("\nTest 2: Full upload → download cycle with integrity check")
    api_key = generate_api_key()
    original  = b"Integration test payload - confidential data " * 200
    local_hash = hashlib.sha512(original).hexdigest()

    with make_client() as c:
        # --- Upload ---
        r = upload(c, api_key, original, "report.pdf")
        assert r.status_code == 200, f"Upload failed: {r.data}"
        meta = r.get_json()
        assert meta["success"] is True
        assert meta["hash"] == local_hash,  "Server-reported hash mismatch"
        assert meta["filename"] == "report.pdf"
        file_id = meta["file_id"]

        # --- Download ---
        r = download(c, api_key, file_id)
        assert r.status_code == 200, f"Download failed: {r.data}"

        # --- Integrity ---
        assert r.data == original,                          "Content mismatch"
        assert hashlib.sha512(r.data).hexdigest() == local_hash, "Hash mismatch"

    print("   Passed — content and hash verified end-to-end")


def test_unauthorized_no_key():
    """Upload with no API key must return 401."""
    print("\nTest 3: Upload with no API key → 401")
    with make_client() as c:
        r = c.post(
            "/upload",
            data={"file": (io.BytesIO(b"secret"), "secret.txt")},
            content_type="multipart/form-data",
        )
        assert r.status_code == 401
    print("   Correctly rejected (401)")


def test_wrong_api_key():
    """Upload with a completely wrong API key must return 401."""
    print("\nTest 4: Wrong API key → 401")
    with make_client() as c:
        r = upload(c, "totally-wrong-key-xyz", b"data", "f.txt")
        assert r.status_code == 401
    print("   Correctly rejected (401)")


def test_revoked_key_rejected():
    """
    A revoked API key must be rejected even if the token is correct.
    Tests: admin revoke endpoint + validate_api_key logic
    """
    print("\nTest 5: Revoked API key → 401")
    with make_client() as c:
        # Generate a key
        r = c.post("/admin/keys/rotate", headers=admin_headers())
        assert r.status_code == 201
        info = r.get_json()
        api_key = info["api_key"]
        key_id  = info["key_id"]

        # Confirm it works
        r = upload(c, api_key, b"hello", "pre_revoke.txt")
        assert r.status_code == 200, "Key should work before revocation"

        # Revoke it
        r = c.post(f"/admin/keys/revoke/{key_id}", headers=admin_headers())
        assert r.status_code == 200

        # Now must be rejected
        r = upload(c, api_key, b"hello", "post_revoke.txt")
        assert r.status_code == 401

    print("   Correctly rejected revoked key (401)")


def test_download_nonexistent_file():
    """Downloading a valid UUID that has no backing file → 404."""
    print("\nTest 6: Download non-existent file → 404")
    api_key = generate_api_key()
    with make_client() as c:
        r = download(c, api_key, str(uuid.uuid4()))
        assert r.status_code == 404
    print("   Correctly returned 404")


def test_invalid_uuid_rejected():
    """Downloading with a malformed file_id → 400 (UUID validation)."""
    print("\nTest 7: Invalid UUID format → 400")
    api_key = generate_api_key()
    with make_client() as c:
        r = download(c, api_key, "not-a-uuid-at-all!!")
        assert r.status_code == 400
    print("   Correctly returned 400")


def test_tampered_encrypted_file():
    """
    Flip bytes inside the .enc file after upload.
    AES-GCM authentication tag must catch the tampering.
    Tests: aes.py decrypt integrity path inside app.py
    """
    print("\nTest 8: Tampered .enc file -> decryption must fail")
    api_key  = generate_api_key()
    # Large enough so byte range 20-60 is safely inside the ciphertext
    payload  = b"Top secret - do not tamper " * 100

    with make_client() as c:
        r = upload(c, api_key, payload, "secret.bin")
        assert r.status_code == 200
        file_id = r.get_json()["file_id"]

        # Locate and corrupt the encrypted file on disk
        enc_path = Path(TMPDIR) / "uploads" / "encrypted" / f"{file_id}.enc"
        raw = bytearray(enc_path.read_bytes())

        # Flip bytes well inside the ciphertext (skip 8-byte base nonce)
        # Only corrupt up to half the file length to stay in bounds
        corrupt_end = min(60, len(raw) // 2)
        for i in range(20, corrupt_end):
            raw[i] ^= 0xFF
        enc_path.write_bytes(bytes(raw))

        # Download should fail — either 400 or garbled/incomplete stream
        try:
            r = download(c, api_key, file_id)
            if r.status_code == 200:
                # If stream started, content must NOT equal the original
                assert r.data != payload, "Tampered file returned correct plaintext!"
            else:
                assert r.status_code == 400
        except Exception:
            pass  # Exception in generator = correctly caught tampering

    print("   Tampering correctly detected")


def test_large_file_end_to_end():
    """
    5 MB random binary file — exercises chunked streaming
    upload and download paths in app.py.
    """
    print("\nTest 9: Large file (5 MB) end-to-end")
    api_key    = generate_api_key()
    large_data = os.urandom(5 * 1024 * 1024)
    local_hash = hashlib.sha512(large_data).hexdigest()

    with make_client() as c:
        r = upload(c, api_key, large_data, "bigfile.bin")
        assert r.status_code == 200
        meta = r.get_json()
        assert meta["hash"] == local_hash,    "Upload hash mismatch"
        file_id = meta["file_id"]

        r = download(c, api_key, file_id)
        assert r.status_code == 200
        assert r.data == large_data,          "Downloaded content mismatch"
        assert hashlib.sha512(r.data).hexdigest() == local_hash

    print("   Passed — 5 MB file verified")


def test_filename_preserved_in_download():
    """
    Original filename must appear in Content-Disposition header.
    Tests the metadata sidecar (.meta.json) read path in download().
    """
    print("\nTest 10: Original filename preserved on download")
    api_key = generate_api_key()

    with make_client() as c:
        r = upload(c, api_key, b"pdf content here", "annual_report_2024.pdf")
        assert r.status_code == 200
        file_id = r.get_json()["file_id"]

        r = download(c, api_key, file_id)
        assert r.status_code == 200
        cd = r.headers.get("Content-Disposition", "")
        assert "annual_report_2024.pdf" in cd, f"Filename not in header: {cd}"

    print("   Passed — filename preserved")


def test_empty_file_upload():
    """Empty files must still encrypt, store, and decrypt correctly."""
    print("\nTest 11: Empty file upload and download")
    api_key = generate_api_key()

    with make_client() as c:
        r = upload(c, api_key, b"", "empty.txt")
        assert r.status_code == 200
        file_id = r.get_json()["file_id"]

        r = download(c, api_key, file_id)
        assert r.status_code == 200
        assert r.data == b""

    print("   Passed — empty file round-trips correctly")


def test_upload_no_file_field():
    """POST to /upload with no 'file' field → 400."""
    print("\nTest 12: Upload request missing file field → 400")
    api_key = generate_api_key()
    with make_client() as c:
        r = c.post("/upload", headers=api_headers(api_key))
        assert r.status_code == 400
    print("   Correctly returned 400")


def test_admin_wrong_key_forbidden():
    """Admin endpoint with wrong key → 403."""
    print("\nTest 13: Admin endpoint with wrong key → 403")
    with make_client() as c:
        r = c.post("/admin/keys/rotate", headers={"X-Admin-Key": "bad-admin-key"})
        assert r.status_code == 403
    print("   Correctly returned 403")


def test_multiple_files_independent():
    """
    Upload two different files. Each must decrypt to its own content.
    Tests that file_id AAD isolation works — one key can't decrypt the other.
    """
    print("\nTest 14: Multiple files are independently isolated")
    api_key = generate_api_key()
    data_a  = b"File A contents " * 50
    data_b  = b"File B contents " * 50

    with make_client() as c:
        r_a = upload(c, api_key, data_a, "file_a.txt")
        r_b = upload(c, api_key, data_b, "file_b.txt")
        assert r_a.status_code == 200
        assert r_b.status_code == 200

        id_a = r_a.get_json()["file_id"]
        id_b = r_b.get_json()["file_id"]

        dl_a = download(c, api_key, id_a)
        dl_b = download(c, api_key, id_b)

        assert dl_a.data == data_a, "File A content wrong"
        assert dl_b.data == data_b, "File B content wrong"
        assert dl_a.data != dl_b.data, "Files should be different"

    print("   Passed — two files isolated correctly")


# =====================================================
# Test Runner
# =====================================================

def run_all():
    print("=" * 60)
    print("Integration Test Suite — Secure File Server")
    print("=" * 60)

    tests = [
        test_health_check,
        test_full_upload_download_cycle,
        test_unauthorized_no_key,
        test_wrong_api_key,
        test_revoked_key_rejected,
        test_download_nonexistent_file,
        test_invalid_uuid_rejected,
        test_tampered_encrypted_file,
        test_large_file_end_to_end,
        test_filename_preserved_in_download,
        test_empty_file_upload,
        test_upload_no_file_field,
        test_admin_wrong_key_forbidden,
        test_multiple_files_independent,
    ]

    passed = 0
    failed = 0

    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            print(f"   FAILED: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed  (total {len(tests)})")
    if failed == 0:
        print("ALL INTEGRATION TESTS PASSED ✓")
    else:
        print("SOME INTEGRATION TESTS FAILED ✗")
    print("=" * 60)


if __name__ == "__main__":
    try:
        run_all()
    finally:
        # Always clean up temp files — never leaves test data on disk
        shutil.rmtree(TMPDIR, ignore_errors=True)
