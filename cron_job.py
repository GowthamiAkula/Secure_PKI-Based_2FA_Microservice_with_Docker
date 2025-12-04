from pathlib import Path
import time

from totp_utils import generate_totp_code

DATA_PATH = Path("/data/seed.txt")
CRON_LOG = Path("/cron/last_code.txt")

def main():
    if not DATA_PATH.exists():
        # Seed not ready yet
        return

    seed_hex = DATA_PATH.read_text(encoding="utf-8").strip()
    code = generate_totp_code(seed_hex)

    now = time.gmtime()  # UTC time
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", now)

    CRON_LOG.parent.mkdir(parents=True, exist_ok=True)
    with CRON_LOG.open("a", encoding="utf-8") as f:
        f.write(f"{timestamp} - 2FA Code: {code}\n")

if __name__ == "__main__":
    main()
