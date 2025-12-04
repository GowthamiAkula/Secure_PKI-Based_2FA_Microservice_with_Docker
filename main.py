from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import os
import time

from decrypt_seed import decrypt_seed
from totp_utils import generate_totp_code, verify_totp_code

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

        # ensure /data exists, then save seed
        DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
        DATA_PATH.write_text(seed_hex, encoding="utf-8")

        return {"status": "ok"}
    except Exception:
        # generic 500 if anything fails
        raise HTTPException(status_code=500, detail="Decryption failed")


# Endpoint 2: GET /generate-2fa
@app.get("/generate-2fa")
def generate_2fa():
    if not DATA_PATH.exists():
        # seed not decrypted/saved yet
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    try:
        seed_hex = DATA_PATH.read_text(encoding="utf-8").strip()
        code = generate_totp_code(seed_hex)

        # remaining seconds in current 30s period
        now = int(time.time())
        remaining = 30 - (now % 30)

        return {"code": code, "valid_for": remaining}
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
        ok = verify_totp_code(seed_hex, body.code, valid_window=1)
        return {"valid": ok}
    except Exception:
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
