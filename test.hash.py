import sys
import hashlib
from pathlib import Path

# Ensure project root is on sys.path so `encryption.*` always resolves,
# whether run from the project root or directly from the tests/ subdirectory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from encryption.hash import generate_hash, verify_hash


def run_tests():
    print("=" * 60)
    print("SHA-512 Integrity Test Suite")
    print("=" * 60)

    all_passed = True

    # --------------------------------------------------
    # Test 1: Basic hash generation and verification
    # --------------------------------------------------
    try:
        print("\nTest 1: Basic hash generation and verification")
        data = b"Highly confidential data"
        hash_value = generate_hash(data)

        assert len(hash_value) == 128, f"Expected 128 hex chars, got {len(hash_value)}"
        assert verify_hash(data, hash_value), "Integrity verification failed"
        print(f"   SHA-512: {hash_value[:32]}...")
        print("   Passed")
    except Exception as e:
        print(f"   Failed: {e}")
        all_passed = False

    # --------------------------------------------------
    # Test 2: Tampering detection
    # --------------------------------------------------
    try:
        print("\nTest 2: Tampering detection")
        data = b"Highly confidential data"
        hash_value = generate_hash(data)
        tampered_data = b"Highly confidential data modified"

        assert not verify_hash(tampered_data, hash_value), "Tampering not detected"
        print("   Passed")
    except Exception as e:
        print(f"   Failed: {e}")
        all_passed = False

    # --------------------------------------------------
    # Test 3: Case-insensitive hash comparison
    # verify_hash must accept uppercase hex strings since
    # external systems may return uppercase SHA-512 hashes.
    # --------------------------------------------------
    try:
        print("\nTest 3: Case-insensitive hash comparison")
        data = b"Highly confidential data"
        hash_value = generate_hash(data)
        uppercase_hash = hash_value.upper()

        assert verify_hash(data, uppercase_hash), "Case-insensitive comparison failed"
        print("   Passed")
    except Exception as e:
        print(f"   Failed: {e}")
        all_passed = False

    # --------------------------------------------------
    # Test 4: Empty data
    # --------------------------------------------------
    try:
        print("\nTest 4: Empty data")
        empty_hash = generate_hash(b"")

        assert len(empty_hash) == 128, f"Expected 128 hex chars, got {len(empty_hash)}"
        assert verify_hash(b"", empty_hash), "Empty data verification failed"
        print("   Passed")
    except Exception as e:
        print(f"   Failed: {e}")
        all_passed = False

    # --------------------------------------------------
    # Test 5: Compatibility with app.py hashlib.sha512
    # app.py computes SHA-512 via hashlib directly and stores
    # hexdigest() — generate_hash must produce the same output.
    # --------------------------------------------------
    try:
        print("\nTest 5: Compatibility with app.py hashlib.sha512")
        data = b"compatibility check"
        expected = hashlib.sha512(data).hexdigest()

        assert generate_hash(data) == expected, "Hash does not match hashlib.sha512"
        assert verify_hash(data, expected), "verify_hash rejects hashlib-produced hash"
        print("   Passed")
    except Exception as e:
        print(f"   Failed: {e}")
        all_passed = False

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------
    print("\n" + "=" * 60)
    if all_passed:
        print("ALL HASH TESTS PASSED")
    else:
        print("SOME HASH TESTS FAILED")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()