import json
import requests

API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws/"

# FILL THIS WITH YOUR REAL STUDENT ID
STUDENT_ID = "23P31A0501"

# EXACT repo URL WITHOUT .git
GITHUB_REPO_URL = "https://github.com/GowthamiAkula/Secure_PKI-Based_2FA_Microservice_with_Docker"


def request_seed(student_id: str, github_repo_url: str, api_url: str):
    # 1. Read student public key from PEM file
    with open("student_public.pem", "r", encoding="utf-8") as f:
        public_key_pem = f.read()

    # 2. Build JSON body
    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key_pem
    }

    # 3. Send POST request
    response = requests.post(
        api_url,
        json=payload,      # send JSON
        timeout=10
    )

    # Debug info so we can see errors
    print("Status:", response.status_code)
    print("Body:", response.text)

    # If status is not 200, this raises an error
    response.raise_for_status()

    # 4. Parse JSON response
    data = response.json()
    encrypted_seed = data.get("encrypted_seed")
    if not encrypted_seed:
        raise ValueError(f"API error: {data}")

    # 5. Save encrypted seed to file (do NOT commit this file)
    with open("encrypted_seed.txt", "w", encoding="utf-8") as f:
        f.write(encrypted_seed)

    print("Saved encrypted_seed.txt")


if __name__ == "__main__":
    request_seed(STUDENT_ID, GITHUB_REPO_URL, API_URL)

