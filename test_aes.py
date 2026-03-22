import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from encryption.aes import generate_key, encrypt_file, decrypt_file


def run_tests():
    print("=" * 60)
    print("AES-256-GCM Test Suite")
    print("=" * 60)

    all_passed = True

    # --------------------------------------------------
    # Test 1: Basic encryption/decryption
    # --------------------------------------------------
    try:
        print("\nTest 1: Basic encryption/decryption")
        key = generate_key()
        data = b"Secure file using AES-256-GCM"
        aad = b"file_id:12345"

        encrypted = encrypt_file(data, key, aad=aad)
        decrypted = decrypt_file(encrypted, key, aad=aad)

        assert data == decrypted
        print("   Passed")

    except Exception as e:
        print(f"   Failed: {e}")
        all_passed = False
        # Remaining tests depend on `encrypted` — stop early
        print("\n" + "=" * 60)
        print("SOME AES TESTS FAILED")
        print("=" * 60)
        return

    # --------------------------------------------------
    # Test 2: Wrong AAD should fail
    # --------------------------------------------------
    try:
        print("\nTest 2: Wrong AAD (should fail)")
        wrong_aad = b"file_id:99999"
        decrypt_file(encrypted, key, aad=wrong_aad)
        print("   Failed: Should have rejected wrong AAD")
        all_passed = False
    except ValueError:
        print("   Correctly rejected wrong AAD")

    # --------------------------------------------------
    # Test 3: Wrong key should fail
    # --------------------------------------------------
    try:
        print("\nTest 3: Wrong key (should fail)")
        wrong_key = generate_key()
        decrypt_file(encrypted, wrong_key, aad=aad)
        print("   Failed: Should have rejected wrong key")
        all_passed = False
    except ValueError:
        print("   Correctly rejected wrong key")

    # --------------------------------------------------
    # Test 4: Empty data
    # --------------------------------------------------
    try:
        print("\nTest 4: Empty data")
        empty_data = b""
        encrypted_empty = encrypt_file(empty_data, key, aad=aad)
        decrypted_empty = decrypt_file(encrypted_empty, key, aad=aad)
        assert empty_data == decrypted_empty
        print("   Passed")
    except Exception as e:
        print(f"   Failed: {e}")
        all_passed = False

    # --------------------------------------------------
    # Test 5: Large data (1 MB)
    # --------------------------------------------------
    try:
        print("\nTest 5: Large data (1 MB)")
        large_data = b"x" * 1_000_000
        encrypted_large = encrypt_file(large_data, key, aad=aad)
        decrypted_large = decrypt_file(encrypted_large, key, aad=aad)
        assert large_data == decrypted_large
        print("   Passed")
    except Exception as e:
        print(f"   Failed: {e}")
        all_passed = False

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------
    print("\n" + "=" * 60)
    if all_passed:
        print("ALL AES TESTS PASSED")
    else:
        print("SOME AES TESTS FAILED")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()