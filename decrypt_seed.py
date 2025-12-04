import base64
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
import string

def decrypt_seed(encrypted_seed_b64: str, private_key_pem: str) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP.

    Args:
        encrypted_seed_b64: Base64-encoded ciphertext
        private_key_pem: RSA private key (PEM text)

    Returns:
        Decrypted hex seed (64-character string)
    """
    # 1. Base64 decode the encrypted seed string -> bytes
    ciphertext = base64.b64decode(encrypted_seed_b64)

    # 2. Load RSA private key from PEM
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )

    # 3. RSA/OAEP decrypt with SHA-256, MGF1(SHA-256), label=None
    plaintext_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 4. Bytes -> UTF-8 string
    seed_hex = plaintext_bytes.decode("utf-8")

    # 5. Validate: must be 64-char hex string
    if len(seed_hex) != 64:
        raise ValueError(f"Seed has wrong length: {len(seed_hex)} (expected 64)")

    hex_chars = set("0123456789abcdef")
    if not all(c in hex_chars for c in seed_hex):
        raise ValueError("Seed contains non-hex characters")

    return seed_hex


if __name__ == "__main__":
    # Read encrypted seed from file (created in step 4)
    with open("encrypted_seed.txt", "r", encoding="utf-8") as f:
        encrypted_seed_b64 = f.read().strip()

    # Read your student private key from PEM file
    with open("student_private.pem", "r", encoding="utf-8") as f:
        private_key_pem = f.read()

    seed_hex = decrypt_seed(encrypted_seed_b64, private_key_pem)
    print("Decrypted seed (hex):", seed_hex)
