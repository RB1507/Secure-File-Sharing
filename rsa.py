import os
import stat
import hashlib
from pathlib import Path
from typing import Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# =====================================================
# Key Directory
# Fix 1: Derive KEY_DIR from this file's location so it
# always resolves correctly regardless of CWD, matching
# the absolute path app.py constructs via Path(".").resolve()
# =====================================================
KEY_DIR = Path(__file__).resolve().parent.parent / "keys"
KEY_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)


# =====================================================
# Generate RSA-2048 Key Pair
# =====================================================
def generate_rsa_keys(
    password: Optional[bytes] = None,
) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # ---- Save private key ----
    private_key_path = KEY_DIR / "private_key.pem"
    encryption_alg = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )

    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_alg,
            )
        )

    os.chmod(private_key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    # ---- Save public key ----
    public_key_path = KEY_DIR / "public_key.pem"
    with open(public_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return private_key, public_key


# =====================================================
# Load Private Key
# Fix 2: Removed deprecated backend=default_backend()
# =====================================================
def load_private_key(password: Optional[bytes] = None) -> rsa.RSAPrivateKey:

    private_key_path = KEY_DIR / "private_key.pem"

    if not private_key_path.exists():
        raise FileNotFoundError("Private key not found")

    with open(private_key_path, "rb") as f:
        key_data = f.read()

    if password is None:
        try:
            return serialization.load_pem_private_key(key_data, password=None)
        except ValueError:
            raise ValueError("Private key is encrypted but no password was provided")
        except Exception as e:
            raise ValueError(f"Failed to load private key: {e}") from e

    try:
        return serialization.load_pem_private_key(key_data, password=password)
    except ValueError as e:
        raise ValueError("Incorrect password or corrupted private key") from e
    except Exception as e:
        raise ValueError(f"Failed to load private key: {e}") from e


# =====================================================
# Load Public Key
# Fix 2: Removed deprecated backend=default_backend()
# =====================================================
def load_public_key() -> rsa.RSAPublicKey:

    public_key_path = KEY_DIR / "public_key.pem"

    if not public_key_path.exists():
        raise FileNotFoundError("Public key not found")

    with open(public_key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# =====================================================
# Check Keys Exist (both must be present together)
# =====================================================
def check_keys_exist() -> bool:
    return (
        (KEY_DIR / "private_key.pem").exists()
        and (KEY_DIR / "public_key.pem").exists()
    )


# =====================================================
# Encrypt AES-256 Key using RSA Public Key
# =====================================================
def encrypt_aes_key(aes_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:

    if not isinstance(aes_key, bytes):
        raise TypeError("AES key must be bytes")

    if len(aes_key) != 32:
        raise ValueError(
            f"Invalid AES key length: {len(aes_key)} bytes. "
            "AES-256 requires exactly 32 bytes."
        )

    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# =====================================================
# Decrypt AES-256 Key using RSA Private Key
# =====================================================
def decrypt_aes_key(
    encrypted_aes_key: bytes,
    private_key: rsa.RSAPrivateKey,
) -> bytes:

    if not isinstance(encrypted_aes_key, bytes):
        raise TypeError("Encrypted AES key must be bytes")

    if len(encrypted_aes_key) != 256:
        raise ValueError(
            f"Invalid encrypted key size: {len(encrypted_aes_key)} bytes. "
            "Expected 256 bytes for RSA-2048."
        )

    return private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# =====================================================
# Public Key Fingerprint Utility
# =====================================================
def get_public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_bytes).hexdigest()[:16]