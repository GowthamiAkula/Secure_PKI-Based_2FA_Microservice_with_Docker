#!/usr/bin/env python3

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import time

from decrypt_seed import decrypt_seed
from totp_utils import generate_totp_code, verify_totp_code

# ==== Step 13: crypto imports ====
import base64
import subprocess
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
# =================================

DATA_PATH = Path("/data/seed.txt")  # will be volume in Docker

app = FastAPI()


class DecryptRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: str


# Endpoint 1: POST /decrypt-seed
@app.post("/decrypt-seed")
def decrypt_seed_endpoint(body: DecryptRequest):
    try:
        # load private key
        priv_pem = Path("student_private.pem").read_text(encoding="utf-8")

        # decrypt using your helper
        seed_hex = decrypt_seed(body.encrypted_seed, priv_pem)

        # ensure data dir exists, then save seed
        DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
        DATA_PATH.write_text(seed_hex, encoding="utf-8")

        return {"status": "ok"}
    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed")


# Endpoint 2: GET /generate-2fa
@app.get("/generate-2fa")
def generate_2fa():
    # seed not decrypted/saved yet
    if not DATA_PATH.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    try:
        seed_hex = DATA_PATH.read_text(encoding="utf-8").strip()
        if not seed_hex:
            raise HTTPException(status_code=500, detail="Seed not decrypted yet")

        # Generate TOTP code within 30s period
        now = int(time.time())
        code = generate_totp_code(seed_hex, now=now)

        # remaining seconds in current 30s period
        remaining = 30 - (now % 30)

        return {"code": code, "valid_for": remaining}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")


# Endpoint 3: POST /verify-2fa
@app.post("/verify-2fa")
def verify_2fa(body: VerifyRequest):
    if not body.code:
        raise HTTPException(status_code=400, detail="Missing code")

    if not DATA_PATH.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    try:
        seed_hex = DATA_PATH.read_text(encoding="utf-8").strip()
        if not seed_hex:
            raise HTTPException(status_code=500, detail="Seed not decrypted yet")

        valid_window = 1  # accept current + previous/next if your helper uses it
        ok = verify_totp_code(seed_hex, body.code, valid_window=valid_window)
        return {"valid": ok}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")


# =====================================================================
# Step 13 helpers: signing and encrypting commit hash for commit proof
# =====================================================================

def sign_message(message: str, private_key) -> bytes:
    """
    Sign a message using RSA-PSS with SHA-256.
    message: ASCII hex string of commit hash.
    """
    msg_bytes = message.encode("utf-8")

    signature = private_key.sign(
        msg_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    """
    Encrypt data using RSA/OAEP with SHA-256.
    """
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def get_latest_commit_hash() -> str:
    """Return 40-character hash of latest Git commit."""
    result = subprocess.run(
        ["git", "log", "-1", "--format=%H"],
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


def generate_commit_proof() -> dict:
    """
    Generate commit proof:
    - sign latest commit hash with student private key (RSA-PSS-SHA256)
    - encrypt signature with instructor public key (RSA-OAEP-SHA256)
    - base64-encode encrypted signature
    """
    root = Path(__file__).resolve().parent

    # 1. Get commit hash
    commit_hash = get_latest_commit_hash()

    # 2. Load student private key
    student_priv = load_private_key(root / "student_private.pem")

    # 3. Sign commit hash
    signature = sign_message(commit_hash, student_priv)

    # 4. Load instructor public key
    instructor_pub = load_public_key(root / "instructor_public.pem")

    # 5. Encrypt signature
    encrypted_sig = encrypt_with_public_key(signature, instructor_pub)

    # 6. Base64 encode
    encoded = base64.b64encode(encrypted_sig).decode("utf-8")

    return {
        "commit_hash": commit_hash,
        "encrypted_signature": encoded,
    }

