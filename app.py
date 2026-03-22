from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, Response
from pathlib import Path
from datetime import datetime, timezone, timedelta
import uuid
import os
import json
import secrets
import re
import threading
import logging
import traceback
import hashlib
import struct
import base64
import hmac

from functools import wraps
from logging.handlers import RotatingFileHandler

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey, InvalidTag

from encryption.aes import generate_key
from encryption.rsa import (
    load_public_key,
    load_private_key,
    generate_rsa_keys,
    encrypt_aes_key,
    decrypt_aes_key,
    check_keys_exist,
)

# =====================================================
# App Setup
# =====================================================

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200/day", "50/hour"],
    storage_uri="memory://",
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("server.log")],
)

# =====================================================
# Directories
# =====================================================

BASE_DIR = Path(".").resolve()
KEY_DIR = BASE_DIR / "keys"
ENC_DIR = BASE_DIR / "uploads" / "encrypted"
AUDIT_DIR = BASE_DIR / "integrity"

for d in (KEY_DIR, ENC_DIR, AUDIT_DIR):
    d.mkdir(parents=True, exist_ok=True)

audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)

handler = RotatingFileHandler(
    AUDIT_DIR / "audit.log",
    maxBytes=5 * 1024 * 1024,
    backupCount=5,
)

handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(handler)

audit_lock = threading.Lock()
key_store_lock = threading.Lock()

# =====================================================
# Environment Variables
# =====================================================

FLASK_ENV = os.environ.get("FLASK_ENV", "development")

RSA_KEY_PASSWORD = os.environ.get("RSA_KEY_PASSWORD")
if not RSA_KEY_PASSWORD:
    if FLASK_ENV == "production":
        raise RuntimeError("RSA_KEY_PASSWORD must be set")
    RSA_KEY_PASSWORD = "dev-password"

RSA_KEY_PASSWORD_BYTES = RSA_KEY_PASSWORD.encode()

ADMIN_MASTER_KEY = os.environ.get("ADMIN_MASTER_KEY")
if not ADMIN_MASTER_KEY:
    raise RuntimeError("ADMIN_MASTER_KEY must be set")

# =====================================================
# UUID Validation
# =====================================================

UUID_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

def valid_uuid(value: str) -> bool:
    return isinstance(value, str) and bool(UUID_REGEX.fullmatch(value))

# =====================================================
# API Key Store
# =====================================================

API_KEYS_FILE = KEY_DIR / "api_keys.json"
KEY_LIFETIME_DAYS = 10


def hash_api_key(raw_key: str, salt: bytes) -> str:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    return base64.b64encode(kdf.derive(raw_key.encode())).decode()


def verify_api_key(raw_key: str, salt: bytes, stored_hash: str) -> bool:
    computed = hash_api_key(raw_key, salt)
    return hmac.compare_digest(computed, stored_hash)


def load_keys():
    if not API_KEYS_FILE.exists():
        return []

    try:
        with open(API_KEYS_FILE, "r") as f:
            data = json.load(f)
            return data.get("keys", [])
    except Exception as e:
        app.logger.error("Failed to read API keys: %s", e)
        return []


def save_keys(keys: list):
    temp = API_KEYS_FILE.with_suffix(".tmp")

    with open(temp, "w") as f:
        json.dump({"keys": keys}, f, indent=2)

    os.replace(temp, API_KEYS_FILE)
    os.chmod(API_KEYS_FILE, 0o600)


def validate_api_key(raw_key: str) -> bool:
    now = datetime.now(timezone.utc)

    with key_store_lock:
        keys = load_keys()

    for entry in keys:
        if not entry.get("active"):
            continue

        if datetime.fromisoformat(entry["expires_at"]) <= now:
            continue

        salt = base64.b64decode(entry["salt"])

        if verify_api_key(raw_key, salt, entry["hash"]):
            return True

    return False


def require_api_key(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        if not api_key or not validate_api_key(api_key):
            return jsonify({"error": "Unauthorized"}), 401
        return func(*args, **kwargs)
    return wrapper


def require_admin(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        admin_key = request.headers.get("X-Admin-Key")
        if not hmac.compare_digest(admin_key or "", ADMIN_MASTER_KEY):
            return jsonify({"error": "Forbidden"}), 403
        return func(*args, **kwargs)
    return wrapper


# =====================================================
# RSA Key Initialization
# =====================================================

def initialize_rsa_keys():
    # Fix 3: Check BOTH keys exist together before deciding to generate.
    # Previously, if only the public key was missing, generate_rsa_keys()
    # would silently overwrite the private key too, making all encrypted
    # files on disk permanently unrecoverable.
    if not check_keys_exist():
        app.logger.info("RSA key pair not found — generating new keys")
        generate_rsa_keys(password=RSA_KEY_PASSWORD_BYTES)
    return load_public_key()


PUBLIC_KEY = initialize_rsa_keys()

# Fix 4: Wrap private key load so a wrong password produces a clean
# RuntimeError at startup instead of a raw ValueError stack trace.
try:
    PRIVATE_KEY = load_private_key(password=RSA_KEY_PASSWORD_BYTES)
except ValueError as e:
    raise RuntimeError(
        f"Failed to load RSA private key — check RSA_KEY_PASSWORD: {e}"
    ) from e

# =====================================================
# Audit Logging
# =====================================================

def audit(event: str, **data):
    record = {
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **data,
    }

    with audit_lock:
        audit_logger.info(json.dumps(record))


# =====================================================
# Admin Endpoints
# =====================================================

@app.route("/admin/keys/rotate", methods=["POST"])
@limiter.limit("5/minute")
@require_admin
def rotate_api_key():
    raw_key = secrets.token_urlsafe(32)
    salt = os.urandom(16)

    now = datetime.now(timezone.utc)

    entry = {
        "id": str(uuid.uuid4()),
        "salt": base64.b64encode(salt).decode(),
        "hash": hash_api_key(raw_key, salt),
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(days=KEY_LIFETIME_DAYS)).isoformat(),
        "active": True,
    }

    with key_store_lock:
        keys = load_keys()
        keys.append(entry)
        save_keys(keys)

    audit("KEY_ROTATED", key_id=entry["id"])

    return jsonify({
        "api_key": raw_key,
        "key_id": entry["id"],
        "expires_at": entry["expires_at"],
    }), 201


@app.route("/admin/keys/revoke/<key_id>", methods=["POST"])
@limiter.limit("5/minute")
@require_admin
def revoke_api_key(key_id):

    with key_store_lock:
        keys = load_keys()

        for entry in keys:
            if entry["id"] == key_id:
                entry["active"] = False
                save_keys(keys)

                audit("KEY_REVOKED", key_id=key_id)
                return jsonify({"status": "revoked"})

    return jsonify({"error": "Key not found"}), 404


# =====================================================
# Upload Endpoint
# =====================================================

@app.route("/upload", methods=["POST"])
@require_api_key
@limiter.limit("10/minute")
def upload():

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    file_id = str(uuid.uuid4())

    enc_path = ENC_DIR / f"{file_id}.enc"
    key_path = ENC_DIR / f"{file_id}.key"
    meta_path = ENC_DIR / f"{file_id}.meta.json"

    try:
        aes_key = generate_key()
        aesgcm = AESGCM(aes_key)

        CHUNK_SIZE = 1024 * 1024
        base_nonce = os.urandom(8)
        counter = 0

        total_size = 0
        file_hash = hashlib.sha512()

        with open(enc_path, "wb") as out_file:

            out_file.write(base_nonce)

            while True:
                chunk = file.stream.read(CHUNK_SIZE)
                if not chunk:
                    break

                total_size += len(chunk)
                file_hash.update(chunk)

                nonce = base_nonce + struct.pack(">I", counter)
                counter += 1

                encrypted = aesgcm.encrypt(
                    nonce,
                    chunk,
                    file_id.encode()
                )

                out_file.write(struct.pack(">I", len(encrypted)))
                out_file.write(encrypted)

        encrypted_key = encrypt_aes_key(aes_key, PUBLIC_KEY)
        key_path.write_bytes(encrypted_key)

        # Write metadata sidecar so original filename is preserved on download
        metadata = {
            "filename": file.filename,
            "size": total_size,
            "hash": file_hash.hexdigest(),
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
        }
        meta_path.write_text(json.dumps(metadata, indent=2))

        os.chmod(enc_path, 0o600)
        os.chmod(key_path, 0o600)
        os.chmod(meta_path, 0o600)

        audit(
            "UPLOAD",
            file_id=file_id,
            filename=file.filename,
            size=total_size,
            hash=file_hash.hexdigest(),
        )

        return jsonify({
            "success": True,
            "file_id": file_id,
            "filename": file.filename,
            "size": total_size,
            "hash": file_hash.hexdigest(),
        })

    except Exception:

        enc_path.unlink(missing_ok=True)
        key_path.unlink(missing_ok=True)
        meta_path.unlink(missing_ok=True)

        app.logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500


# =====================================================
# Download Endpoint
# =====================================================

@app.route("/download/<file_id>", methods=["GET"])
@require_api_key
@limiter.limit("20/minute")
def download(file_id):

    if not valid_uuid(file_id):
        return jsonify({"error": "Invalid file ID"}), 400

    enc_path = ENC_DIR / f"{file_id}.enc"
    key_path = ENC_DIR / f"{file_id}.key"

    if not enc_path.exists() or not key_path.exists():
        return jsonify({"error": "File not found"}), 404

    try:

        encrypted_key = key_path.read_bytes()
        aes_key = decrypt_aes_key(encrypted_key, PRIVATE_KEY)

        def generate():

            with open(enc_path, "rb") as f:

                base_nonce = f.read(8)
                counter = 0
                aesgcm = AESGCM(aes_key)

                while True:

                    length_bytes = f.read(4)
                    if not length_bytes:
                        break

                    chunk_length = struct.unpack(">I", length_bytes)[0]
                    encrypted_chunk = f.read(chunk_length)

                    nonce = base_nonce + struct.pack(">I", counter)
                    counter += 1

                    yield aesgcm.decrypt(
                        nonce,
                        encrypted_chunk,
                        file_id.encode()
                    )

        audit("DOWNLOAD", file_id=file_id)

        meta_path = ENC_DIR / f"{file_id}.meta.json"
        filename = f"{file_id}.bin"

        if meta_path.exists():
            try:
                metadata = json.loads(meta_path.read_text())
                filename = metadata.get("filename", filename)
            except Exception:
                pass

        return Response(
            generate(),
            mimetype="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            },
        )

    except (InvalidKey, InvalidTag):
        return jsonify({"error": "Decryption failed"}), 400

    except Exception:
        app.logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500


# =====================================================
# Health Check
# =====================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# =====================================================
# Entry Point
# =====================================================

if __name__ == "__main__":

    app.logger.info("Secure File Server starting")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        threaded=True,
    )