import sys
import os
import tempfile
import shutil
from pathlib import Path

# Ensure project root is on sys.path so `encryption.*` always resolves,
# whether run from the project root or directly from the tests/ subdirectory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import encryption.rsa as rsa_module
from encryption.rsa import (
    generate_rsa_keys,
    encrypt_aes_key,
    decrypt_aes_key,
    load_private_key,
)
from encryption.aes import generate_key
class IsolatedKeyDir:
    """Context manager that redirects rsa_module.KEY_DIR to a temp dir."""

    def __enter__(self):
        self._original = rsa_module.KEY_DIR
        self._tmpdir = tempfile.mkdtemp()
        rsa_module.KEY_DIR = Path(self._tmpdir)
        return Path(self._tmpdir)

    def __exit__(self, *_):
        rsa_module.KEY_DIR = self._original
        shutil.rmtree(self._tmpdir, ignore_errors=True)


def run_rsa_tests():
    print("=" * 60)
    print("RSA-2048 + AES-256 Key Exchange Test Suite")
    print("=" * 60)

    all_passed = True

    # --------------------------------------------------
    # Test 1: Basic RSA encryption/decryption
    # Uses isolated dir — does not touch production keys.
    # --------------------------------------------------
    try:
        print("\nTest 1: Basic RSA encryption/decryption")
        with IsolatedKeyDir():
            private_key, public_key = generate_rsa_keys()
            aes_key = generate_key()

            encrypted = encrypt_aes_key(aes_key, public_key)
            decrypted = decrypt_aes_key(encrypted, private_key)

            assert aes_key == decrypted
        print("   Passed")
    except Exception as e:
        print(f"   Failed: {e}")
        all_passed = False

    # --------------------------------------------------
    # Test 2: RSA with password-protected private key
    # Uses isolated dir — writes password-protected keys to
    # temp location, not production keys/.
    # --------------------------------------------------
    try:
        print("\nTest 2: RSA with password protection")
        password = b"test-password-123"

        with IsolatedKeyDir():
            private_key, public_key = generate_rsa_keys(password=password)
            aes_key = generate_key()

            encrypted = encrypt_aes_key(aes_key, public_key)
            decrypted = decrypt_aes_key(encrypted, private_key)

            assert aes_key == decrypted
            print("   Passed (in-memory keys)")

            # Load private key from disk — still within isolated dir
            loaded_private = load_private_key(password=password)
            decrypted_loaded = decrypt_aes_key(encrypted, loaded_private)

            assert aes_key == decrypted_loaded
            print("   Passed (loaded from disk)")

    except Exception as e:
        print(f"   Failed: {e}")
        all_passed = False

    # --------------------------------------------------
    # Test 3: Invalid AES key size (should fail)
    # --------------------------------------------------
    try:
        print("\nTest 3: Invalid AES key size (should fail)")
        with IsolatedKeyDir():
            _, public_key = generate_rsa_keys()
            wrong_aes_key = os.urandom(64)  # Not 32 bytes

            encrypt_aes_key(wrong_aes_key, public_key)
            print("   Failed: Oversized AES key was accepted")
            all_passed = False

    except ValueError as e:
        print(f"   Correctly rejected: {str(e)[:60]}...")

    # --------------------------------------------------
    # Test 4: AES-256 only enforcement
    # --------------------------------------------------
    try:
        print("\nTest 4: AES-256 only enforcement")
        with IsolatedKeyDir():
            private_key, public_key = generate_rsa_keys()
            aes_key = generate_key()  # Always 32 bytes

            encrypted = encrypt_aes_key(aes_key, public_key)
            decrypted = decrypt_aes_key(encrypted, private_key)

            assert aes_key == decrypted
        print("   AES-256 accepted and decrypted correctly")

    except Exception as e:
        print(f"   Failed: {e}")
        all_passed = False

    # --------------------------------------------------
    # Test 5: Wrong encrypted data size (should fail)
    # --------------------------------------------------
    try:
        print("\nTest 5: Wrong encrypted data size")
        with IsolatedKeyDir():
            private_key, _ = generate_rsa_keys()
            wrong_data = os.urandom(100)  # RSA-2048 expects 256 bytes

            decrypt_aes_key(wrong_data, private_key)
            print("   Failed: Invalid ciphertext size accepted")
            all_passed = False

    except ValueError as e:
        print(f"   Correctly rejected: {str(e)[:60]}...")

    # --------------------------------------------------
    # Test 6: Wrong RSA key pair (should fail)
    # Second key pair is generated in memory only to avoid
    # overwriting the first pair written to the isolated dir.
    # --------------------------------------------------
    try:
        print("\nTest 6: Wrong RSA key pair")
        with IsolatedKeyDir():
            private_key_1, public_key_1 = generate_rsa_keys()

            # Generate second key pair purely in memory — no disk write
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
            private_key_2 = _rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            aes_key = generate_key()
            encrypted = encrypt_aes_key(aes_key, public_key_1)

            decrypt_aes_key(encrypted, private_key_2)
            print("   Failed: Wrong private key decrypted data")
            all_passed = False

    except ValueError as e:
        print(f"   Correctly rejected: {str(e)[:60]}...")

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------
    print("\n" + "=" * 60)
    if all_passed:
        print("ALL RSA TESTS PASSED")
    else:
        print("SOME RSA TESTS FAILED")
    print("=" * 60)


def minimal_test():
    """Minimal sanity test — isolated from production keys."""
    print("\nMinimal RSA test:")
    try:
        with IsolatedKeyDir():
            private_key, public_key = generate_rsa_keys()
            aes_key = generate_key()

            encrypted = encrypt_aes_key(aes_key, public_key)
            decrypted = decrypt_aes_key(encrypted, private_key)

            assert aes_key == decrypted
        print("   RSA-2048 AES-256 key exchange successful")
    except Exception as e:
        print(f"   Error: {e}")


if __name__ == "__main__":
    run_rsa_tests()
    minimal_test()