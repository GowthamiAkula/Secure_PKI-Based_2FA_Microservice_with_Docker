#!/usr/bin/env python3
# Cron script to log 2FA codes every minute

import sys
from pathlib import Path
import time

# Ensure /app is on sys.path so totp_utils can be imported
APP_DIR = Path("/app")
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from totp_utils import generate_totp_code

SEED_PATH = Path("/data/seed.txt")
LOG_PATH = Path("/cron/last_code.txt")


def main():
    # 1. Read hex seed (handle missing file gracefully)
    if not SEED_PATH.exists():
        return
    seed_hex = SEED_PATH.read_text(encoding="utf-8").strip()
    if not seed_hex:
        return

    # 2. Generate TOTP code using existing helper
    code = generate_totp_code(seed_hex)

    # 3. Get current UTC timestamp
    now = time.gmtime()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", now)

    # 4. Append formatted line
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(f"{timestamp} - 2FA Code: {code}\n")


if __name__ == "__main__":
    main()

