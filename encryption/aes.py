import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# -------------------------------------------------
# Generate AES-256 Key (32 bytes = 256 bits)
# -------------------------------------------------
def generate_key() -> bytes:
    """Generate a 256-bit (32-byte) AES key."""
    return AESGCM.generate_key(bit_length=256)

# -------------------------------------------------
# Validate AES-256 Key
# -------------------------------------------------
def validate_key(key: bytes) -> None:
    """Ensure strict AES-256 usage."""
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("AES key must be bytes")

    if len(key) != 32:
        raise ValueError(
            f"Invalid AES key length: {len(key)} bytes. "
            "AES-256 requires exactly 32 bytes."
        )

# -------------------------------------------------
# Encrypt File Data using AES-256-GCM
# -------------------------------------------------
def encrypt_file(
    file_data: bytes,
    key: bytes,
    aad: bytes = b""
) -> bytes:
    validate_key(key)

    if not isinstance(file_data, (bytes, bytearray)):
        raise TypeError("File data must be bytes")

    # Generate secure random nonce (12 bytes recommended for GCM)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)

    # Encrypt (ciphertext includes 16-byte authentication tag)
    ciphertext = aesgcm.encrypt(
        nonce=nonce,
        data=file_data,
        associated_data=aad
    )

    # Store nonce + ciphertext
    return nonce + ciphertext

# -------------------------------------------------
# Decrypt File Data using AES-256-GCM
# -------------------------------------------------
def decrypt_file(
    encrypted_data: bytes,
    key: bytes,
    aad: bytes = b""
) -> bytes:
    validate_key(key)

    if not isinstance(encrypted_data, (bytes, bytearray)):
        raise TypeError("Encrypted data must be bytes")

    # Minimum length: 12-byte nonce + 16-byte auth tag
    if len(encrypted_data) < 28:
        raise ValueError(
            f"Encrypted data too short ({len(encrypted_data)} bytes). "
            "Minimum required is 28 bytes."
        )

    # Extract nonce and ciphertext
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(
            nonce=nonce,
            data=ciphertext,
            associated_data=aad
        )
        return plaintext

    except InvalidTag:
        raise ValueError(
            "Decryption failed: authentication tag mismatch. "
            "Data may be corrupted, tampered with, or key/AAD is incorrect."
        )
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")
