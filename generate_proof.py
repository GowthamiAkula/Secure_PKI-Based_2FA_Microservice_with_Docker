#!/usr/bin/env python3

import base64
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from main import sign_message, encrypt_with_public_key
  # adjust import to your file name


ROOT = Path(__file__).resolve().parent


def get_latest_commit_hash() -> str:
    """Return 40-character hash of latest commit."""
    result = subprocess.run(
        ["git", "log", "-1", "--format=%H"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def load_private_key(path: Path):
    pem = path.read_bytes()
    return serialization.load_pem_private_key(pem, password=None)


def load_public_key(path: Path):
    pem = path.read_bytes()
    return serialization.load_pem_public_key(pem)


def main():
    # 1. Get commit hash
    commit_hash = get_latest_commit_hash()

    # 2. Load student private key
    student_priv = load_private_key(ROOT / "student_private.pem")

    # 3. Sign commit hash
    signature = sign_message(commit_hash, student_priv)

    # 4. Load instructor public key
    instructor_pub = load_public_key(ROOT / "instructor_public.pem")

    # 5. Encrypt signature
    encrypted_sig = encrypt_with_public_key(signature, instructor_pub)

    # 6. Base64-encode encrypted signature
    encoded = base64.b64encode(encrypted_sig).decode("utf-8")

    # Output in the format the assignment wants
    print("Commit Hash:", commit_hash)
    print("Encrypted Signature:", encoded)


if __name__ == "__main__":
    main()
