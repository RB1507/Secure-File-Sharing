import os
import sys
import json
import hashlib
import base64
import getpass
import tempfile
import time
import requests
from pathlib import Path
from urllib.parse import urljoin
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# =====================================================
# Configuration
# =====================================================
DEFAULT_BASE_URL = "http://127.0.0.1:5000"
CONFIG_FILE = Path("client_config.json")
KEYSTORE_FILE = Path("keys/api_key.enc")
DOWNLOAD_DIR = Path("downloads")

TIMEOUT = 30
MAX_FILE_SIZE = 1024 * 1024 * 1024
READ_CHUNK_SIZE = 8192
SESSION_TTL_SECONDS = 8 * 60 * 60  # 8 hours

DOWNLOAD_DIR.mkdir(exist_ok=True)
KEYSTORE_FILE.parent.mkdir(exist_ok=True)

# =====================================================
# Session Cache — passphrase asked once per day
# Stores the decrypted API key in a temp file for 8 hours.
# =====================================================
def _session_file() -> Path:
    """
    Unique temp file per keystore so different projects don't collide.
    """
    uid = hashlib.sha256(str(KEYSTORE_FILE.resolve()).encode()).hexdigest()[:12]
    return Path(tempfile.gettempdir()) / f".sfc_session_{uid}"


def _save_session(api_key: str):
    sf = _session_file()
    data = {"key": api_key, "expires": time.time() + SESSION_TTL_SECONDS}
    sf.write_text(json.dumps(data))
    try:
        sf.chmod(0o600)
    except Exception:
        pass  # Windows doesn't always support chmod


def _load_session() -> Optional[str]:
    sf = _session_file()
    if not sf.exists():
        return None
    try:
        data = json.loads(sf.read_text())
        if time.time() < data["expires"]:
            return data["key"]
        sf.unlink(missing_ok=True)
    except Exception:
        pass
    return None


def _clear_session():
    _session_file().unlink(missing_ok=True)


# =====================================================
# Config
# =====================================================
def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {"base_url": DEFAULT_BASE_URL}


def save_config(cfg: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


CONFIG = load_config()
BASE_URL = CONFIG.get("base_url", DEFAULT_BASE_URL)

# =====================================================
# Key Derivation
# =====================================================
def derive_key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(passphrase.encode())


# =====================================================
# Encrypted API Key Store
# =====================================================
def store_api_key_encrypted(api_key: str):
    passphrase = getpass.getpass("Create a passphrase to protect your key: ")
    confirm = getpass.getpass("Confirm passphrase: ")

    if passphrase != confirm:
        print("Passphrases do not match.")
        sys.exit(1)

    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, api_key.encode(), None)

    with open(KEYSTORE_FILE, "w") as f:
        json.dump({
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }, f, indent=2)

    # Cache immediately so the user isn't asked again right after setup
    _save_session(api_key)
    print("API key saved.")


def load_api_key() -> str:
    # 1. Check session cache first — no passphrase needed
    cached = _load_session()
    if cached:
        return cached

    # 2. Cache miss — ask once, then save to session
    if not KEYSTORE_FILE.exists():
        print("No API key found. Run  'python client.py setup'  first.")
        sys.exit(1)

    with open(KEYSTORE_FILE, "r") as f:
        data = json.load(f)

    passphrase = getpass.getpass("Passphrase: ")
    salt  = base64.b64decode(data["salt"])
    nonce = base64.b64decode(data["nonce"])
    ct    = base64.b64decode(data["ciphertext"])

    try:
        api_key = AESGCM(derive_key(passphrase, salt)).decrypt(nonce, ct, None).decode()
    except Exception:
        print("Wrong passphrase.")
        sys.exit(1)

    _save_session(api_key)   # remember for the rest of the day
    return api_key


def auth_headers() -> dict:
    return {"X-API-Key": load_api_key()}


# =====================================================
# HTTP helper
# =====================================================
def http_request(method, endpoint, require_auth=True, extra_headers=None, **kwargs):
    try:
        headers = auth_headers() if require_auth else {}
        if extra_headers:
            headers.update(extra_headers)
        return requests.request(
            method=method,
            url=urljoin(BASE_URL, endpoint),
            headers=headers,
            timeout=TIMEOUT,
            **kwargs,
        )
    except requests.exceptions.ConnectionError:
        print(f"\nCannot connect to server at: {BASE_URL}")
        print("  - Is the server running?")
        print("  - Run 'python client.py setup' to change the server address")
        sys.exit(1)
    except requests.RequestException as exc:
        print("Network error:", exc)
        sys.exit(1)


def check_server_health():
    r = http_request("GET", "/health", require_auth=False)
    if r.status_code != 200:
        print("Server health check failed.")
        sys.exit(1)


# =====================================================
# Setup — only 2 questions
# =====================================================
def setup_wizard():
    print("\n=== Secure File Client — Setup ===\n")

    # Question 1: server address
    current = CONFIG.get("base_url", DEFAULT_BASE_URL)
    url = input(f"Server address [{current}]: ").strip()
    if url:
        cfg = load_config()
        cfg["base_url"] = url.rstrip("/")
        save_config(cfg)
        global BASE_URL
        BASE_URL = cfg["base_url"]
    else:
        BASE_URL = current

    # Quick reachability check
    print(f"Connecting to {BASE_URL} ...")
    try:
        r = requests.get(urljoin(BASE_URL, "/health"), timeout=TIMEOUT)
        print("Server is reachable ✓" if r.status_code == 200 else f"Got status {r.status_code} — continuing anyway.")
    except Exception:
        print("Warning: Could not reach server. Check the address and try again.")

    # Question 2: API key
    api_key = getpass.getpass("\nAPI key (from your admin): ").strip()
    if not api_key:
        print("No API key entered. Run setup again when you have one.")
        return

    store_api_key_encrypted(api_key)

    print("\n✓ Ready! Commands:")
    print("  python client.py upload   <file>")
    print("  python client.py download <file_id>")


# =====================================================
# Admin commands
# =====================================================
def admin_gen_key():
    admin_key = getpass.getpass("Admin master key: ").strip()
    r = http_request("POST", "/admin/keys/rotate", require_auth=False,
                     extra_headers={"X-Admin-Key": admin_key})
    if r.status_code == 201:
        data = r.json()
        print("\n✓ New API key generated:")
        print(f"  API Key  : {data['api_key']}")
        print(f"  Key ID   : {data['key_id']}")
        print(f"  Expires  : {data['expires_at']}")
        print("\nShare the API key with the user — they run: python client.py setup")
    elif r.status_code == 403:
        print("Wrong admin key.")
    else:
        print(f"Error {r.status_code}: {r.text}")


def admin_revoke_key():
    admin_key = getpass.getpass("Admin master key: ").strip()
    key_id = input("Key ID to revoke: ").strip()
    r = http_request("POST", f"/admin/keys/revoke/{key_id}", require_auth=False,
                     extra_headers={"X-Admin-Key": admin_key})
    if r.status_code == 200:
        print(f"Key {key_id} revoked.")
    elif r.status_code == 403:
        print("Wrong admin key.")
    elif r.status_code == 404:
        print("Key ID not found.")
    else:
        print(f"Error {r.status_code}: {r.text}")


# =====================================================
# Upload
# =====================================================
def sha512_file(path: Path) -> str:
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(READ_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def upload_file(path_str: str):
    path = Path(path_str).resolve()
    if not path.exists() or not path.is_file():
        print("File not found:", path)
        return
    if path.stat().st_size > MAX_FILE_SIZE:
        print("File too large (max 100 MB)")
        return

    local_hash = sha512_file(path)
    print(f"Uploading: {path.name} ...")

    with open(path, "rb") as f:
        r = http_request("POST", "/upload", files={"file": (path.name, f)})

    if r.status_code == 401:
        _clear_session()
        print("Unauthorized — run 'python client.py setup' to fix your API key.")
        return
    if r.status_code != 200:
        print("Upload failed:", r.text)
        return

    data = r.json()
    if data.get("hash") != local_hash:
        print("Integrity check failed — file may be corrupted in transit.")
        return

    print(f"\n✓ Upload successful!")
    print(f"  File ID  : {data['file_id']}")
    print(f"  Filename : {data.get('filename', path.name)}")
    print(f"  Size     : {data['size']} bytes")
    print(f"\nDownload on any machine:")
    print(f"  python client.py download {data['file_id']}")


# =====================================================
# Download
# =====================================================
def _safe_filename(response, file_id: str) -> str:
    cd = response.headers.get("Content-Disposition", "")
    if 'filename="' in cd:
        try:
            raw = cd.split('filename="')[1].rstrip('"')
            safe = Path(raw).name
            if safe:
                return safe
        except IndexError:
            pass
    return f"{file_id}.bin"


def download_file(file_id: str, output_name: Optional[str] = None):
    print(f"Downloading ...")
    r = http_request("GET", f"/download/{file_id}", stream=True)

    if r.status_code == 401:
        _clear_session()
        print("Unauthorized — run 'python client.py setup' to fix your API key.")
        return
    if r.status_code == 404:
        print("File not found on server.")
        return
    if r.status_code != 200:
        print("Download failed:", r.text)
        return

    output_path = Path(output_name).resolve() if output_name else DOWNLOAD_DIR / _safe_filename(r, file_id)

    with open(output_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=READ_CHUNK_SIZE):
            if chunk:
                f.write(chunk)

    print(f"✓ Saved to: {output_path}")
    print(f"  Size: {output_path.stat().st_size} bytes")


# =====================================================
# CLI
# =====================================================
def print_usage():
    print("""
Usage:
  python client.py setup                        First-time setup
  python client.py upload   <file>              Upload a file
  python client.py download <file_id>           Download a file
  python client.py download <file_id> <name>    Download and rename

Admin:
  python client.py admin gen-key                Generate API key for a user
  python client.py admin revoke-key             Revoke an API key
""")


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "setup":
        setup_wizard()

    elif cmd == "admin":
        sub = sys.argv[2].lower() if len(sys.argv) > 2 else ""
        check_server_health()
        if sub == "gen-key":
            admin_gen_key()
        elif sub == "revoke-key":
            admin_revoke_key()
        else:
            print("Usage: python client.py admin [gen-key | revoke-key]")

    elif cmd == "upload" and len(sys.argv) == 3:
        upload_file(sys.argv[2])

    elif cmd == "download" and len(sys.argv) >= 3:
        download_file(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)

    else:
        print_usage()


if __name__ == "__main__":
    main()