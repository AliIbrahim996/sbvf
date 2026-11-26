"""Authentication primitives for the optional multi-user layer.

Everything here is **stdlib-only and pure** (no DB, no third-party dependency),
so it unit-tests without a database: password hashing, session-token generation,
and the opt-in flag. The DB-backed user/session rows live in
:mod:`sbvf.store.repository`; the server wiring lives in ``ui/server.py``.

Multi-user is **opt-in**: it is active only when a database is configured *and*
``SBVF_AUTH`` is set. With it off (the default) the dashboard behaves exactly as
before — no login, scans unscoped — so local dev and the existing tests are
unaffected.

Design notes:
  * passwords are hashed with ``hashlib.scrypt`` (memory-hard) and a per-user
    random salt, encoded as ``scrypt$<n>$<r>$<p>$<salt_b64>$<hash_b64>``;
  * verification is constant-time (:func:`hmac.compare_digest`) and never raises
    on a malformed stored value — it just returns ``False``;
  * session tokens are random (:mod:`secrets`) and stored **hashed** at rest, so
    reading the ``sessions`` table never exposes a usable token (mirrors the
    secret-masking care in ``sbvf/sast/rules.py``).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from . import db

# scrypt cost parameters (n must be a power of two). n=16384,r=8,p=1 needs
# ~16 MiB, within scrypt's default memory limit.
_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1
_DKLEN = 32
_SALT_BYTES = 16

SESSION_COOKIE = "sbvf_session"
SESSION_TTL_SECONDS = 7 * 24 * 3600          # 7 days
_MIN_PASSWORD_LEN = 8
_MIN_USERNAME_LEN = 3


def _truthy(val) -> bool:
    return str(val).strip().lower() in ("1", "true", "yes", "on")


def auth_enabled() -> bool:
    """True when multi-user auth is active: a DB is configured AND SBVF_AUTH is set."""
    return db.is_enabled() and _truthy(os.environ.get("SBVF_AUTH"))


def cookie_secure() -> bool:
    """Whether to mark the session cookie ``Secure`` (HTTPS-only).

    Defaults off so it works over plain http on localhost; set ``SBVF_COOKIE_SECURE``
    when the dashboard is served over HTTPS.
    """
    return _truthy(os.environ.get("SBVF_COOKIE_SECURE"))


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def hash_password(password: str) -> str:
    """Hash *password* with scrypt and a fresh random salt; return an encoded string."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    salt = secrets.token_bytes(_SALT_BYTES)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_DKLEN)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of *password* against an encoded *stored* hash.

    Returns ``False`` for any malformed stored value instead of raising, so a
    corrupt row can never crash a login.
    """
    if not isinstance(password, str) or not isinstance(stored, str):
        return False
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = _unb64(salt_b64)
        expected = _unb64(hash_b64)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                            n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


def new_session_token() -> str:
    """A fresh, URL-safe, high-entropy session token (the value stored in the cookie)."""
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    """SHA-256 of a session token — what is stored in the DB, so the table never
    holds a usable token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def password_problem(password: str) -> str:
    """Return a human-readable reason *password* is unacceptable, or '' if it is OK."""
    if not isinstance(password, str) or len(password) < _MIN_PASSWORD_LEN:
        return f"password must be at least {_MIN_PASSWORD_LEN} characters"
    return ""


def username_problem(username: str) -> str:
    """Return a human-readable reason *username* is unacceptable, or '' if it is OK."""
    if not isinstance(username, str):
        return "username is required"
    name = username.strip()
    if len(name) < _MIN_USERNAME_LEN:
        return f"username must be at least {_MIN_USERNAME_LEN} characters"
    if not all(c.isalnum() or c in "_-.@" for c in name):
        return "username may contain only letters, digits and _ - . @"
    return ""
