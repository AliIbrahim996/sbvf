"""Intentionally vulnerable crypto sample (OWASP A04) with safe counterparts."""
import hashlib
import os
import random
import secrets

import bcrypt
import requests

# ---- VULNERABLE -----------------------------------------------------------
SECRET_KEY = "s3cr3t-hardcoded-key-123"          # hardcoded_secret


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()           # weak_crypto


def fetch_partner(url):
    return requests.get(url, verify=False)                      # broken_tls


def make_reset_token():
    return str(random.randint(100000, 999999))                  # weak_random (token)


# ---- SAFE counterparts ----------------------------------------------------
API_KEY = os.environ["API_KEY"]                                 # from environment


def hash_password_safe(password):
    digest = hashlib.sha256(password.encode()).hexdigest()
    return bcrypt.hashpw(digest.encode(), bcrypt.gensalt())


def fetch_partner_safe(url):
    return requests.get(url, verify=True, timeout=5)


def make_reset_token_safe():
    return secrets.token_hex(16)


def pick_greeting():
    return random.choice(["hi", "hello"])                       # harmless: UI text only
