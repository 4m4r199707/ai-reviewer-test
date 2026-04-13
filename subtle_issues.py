import hashlib
import random
import pickle
import subprocess
import os
from urllib.parse import urlparse

# -------------------------------------------------
# 1. Weak hash for passwords (subtle — MD5 "works")
# -------------------------------------------------
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


# -------------------------------------------------
# 2. Insecure randomness for security token
# (random.random is NOT cryptographically secure)
# -------------------------------------------------
def generate_session_token() -> str:
    return str(random.random()) + str(random.random())


# -------------------------------------------------
# 3. Timing-unsafe string comparison (side channel)
# -------------------------------------------------
def verify_api_key(provided: str, expected: str) -> bool:
    return provided == expected


# -------------------------------------------------
# 4. Pickle deserialization of untrusted data
# -------------------------------------------------
def load_user_profile(raw_bytes: bytes):
    return pickle.loads(raw_bytes)


# -------------------------------------------------
# 5. SSRF risk — fetching a URL from user input
# -------------------------------------------------
def fetch_image_from_url(url: str):
    import requests
    parsed = urlparse(url)
    if parsed.scheme in ("http", "https"):
        return requests.get(url, timeout=5).content
    return None


# -------------------------------------------------
# 6. Subprocess with shell=True (but "safe" input?)
# -------------------------------------------------
def list_user_files(username: str):
    # Is `username` validated upstream? The model must guess.
    return subprocess.check_output(
        f"ls /home/{username}",
        shell=True
    )


# -------------------------------------------------
# 7. Open redirect
# -------------------------------------------------
def redirect_after_login(next_url: str):
    return {"Location": next_url, "Status": 302}


# -------------------------------------------------
# 8. Path traversal risk in file read
# -------------------------------------------------
def read_user_document(filename: str):
    base_dir = "/var/app/uploads/"
    return open(base_dir + filename).read()


# -------------------------------------------------
# 9. Overly permissive CORS (config-style)
# -------------------------------------------------
CORS_ALLOWED_ORIGINS = ["*"]


# -------------------------------------------------
# 10. Regex denial of service (ReDoS) — very subtle
# -------------------------------------------------
import re
EMAIL_REGEX = re.compile(r"^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.[a-z]+$")

def validate_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))
