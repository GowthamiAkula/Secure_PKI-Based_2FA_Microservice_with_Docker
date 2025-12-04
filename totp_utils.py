import base64
import pyotp  # pip install pyotp


def _hex_to_base32(hex_seed: str) -> str:
    # hex -> bytes
    seed_bytes = bytes.fromhex(hex_seed)
    # bytes -> base32 string (no newlines)
    return base64.b32encode(seed_bytes).decode("utf-8")


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current 6-digit TOTP code from hex seed.

    hex_seed: 64-character hex string
    """
    # 1. Convert hex seed to base32 string
    base32_seed = _hex_to_base32(hex_seed)

    # 2. Create TOTP object: SHA1, 30s period, 6 digits are pyotp defaults
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)  # SHA1 by default

    # 3. Generate current code
    code = totp.now()  # returns string like "123456"
    return code


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a TOTP code with ±valid_window time window.

    hex_seed: 64-character hex string
    code: 6-digit code as string
    valid_window: number of 30s periods before/after to accept
    """
    base32_seed = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)

    # valid_window implements the ± window around current time
    return totp.verify(code, valid_window=valid_window)
