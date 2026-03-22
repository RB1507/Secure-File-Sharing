import hashlib
from pathlib import Path

def generate_hash(data: bytes) -> str:
    
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes")

    sha = hashlib.sha512()
    sha.update(data)
    return sha.hexdigest()

def hash_file(file_path: str | Path) -> str:

    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not file_path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")
    
    sha = hashlib.sha512()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)

    return sha.hexdigest()

def verify_hash(data: bytes, expected_hash: str) -> bool:

    calculated = generate_hash(data)
    return calculated.lower() == expected_hash.lower()

def verify_file_hash(file_path: str | Path, expected_hash: str) -> bool:

    calculated = hash_file(file_path)
    return calculated.lower() == expected_hash.lower()
