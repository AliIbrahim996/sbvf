"""Connection handling for the optional PostgreSQL persistence layer.

Persistence is entirely optional: if ``DATABASE_URL`` is not set, or psycopg is
not installed, or the database is unreachable, :func:`get_pool` returns ``None``
and the rest of the application runs exactly as before (scans still stream, they
are simply not stored). Nothing here is imported by the stdlib-only core scanner.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Optional

_pool = None
_lock = threading.Lock()
_last_fail = 0.0
_RETRY_AFTER = 30.0  # seconds to wait before retrying pool creation after a failure


def database_url() -> Optional[str]:
    """Resolve the connection string from the environment, or None if unset."""
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    host = os.environ.get("SBVF_DB_HOST")
    if not host:
        return None
    user = os.environ.get("SBVF_DB_USER", "sbvf")
    pwd = os.environ.get("SBVF_DB_PASSWORD", "sbvf")
    name = os.environ.get("SBVF_DB_NAME", "sbvf")
    port = os.environ.get("SBVF_DB_PORT", "5432")
    return f"postgresql://{user}:{pwd}@{host}:{port}/{name}"


def is_enabled() -> bool:
    """True when a connection string is configured (psycopg presence checked lazily)."""
    return database_url() is not None


def get_pool():
    """Return a shared connection pool, or None if persistence is unavailable.

    Created once and reused. A creation failure (missing driver, bad URL, server
    down) is swallowed and reported as None so callers degrade gracefully; it is
    retried after ``_RETRY_AFTER`` seconds rather than disabling persistence for
    the whole process lifetime after a transient blip.
    """
    global _pool, _last_fail
    if _pool is not None:
        return _pool
    url = database_url()
    if not url:
        return None
    with _lock:
        if _pool is not None:
            return _pool
        if _last_fail and (time.monotonic() - _last_fail) < _RETRY_AFTER:
            return None  # still in the backoff window
        try:
            from psycopg_pool import ConnectionPool  # lazy: optional dependency

            pool = ConnectionPool(
                conninfo=url, min_size=1, max_size=int(os.environ.get("SBVF_DB_POOL", "5")),
                kwargs={"autocommit": False}, open=True, timeout=10,
            )
            # Validate connectivity once up front.
            with pool.connection() as conn:
                conn.execute("SELECT 1")
            _pool = pool
            _last_fail = 0.0
            return _pool
        except Exception as exc:  # driver missing / server unreachable
            print(f"[sbvf.store] persistence unavailable (will retry): {exc}")
            _last_fail = time.monotonic()
            return None


def reset_for_tests() -> None:
    """Drop the cached pool so a test can reconfigure the environment."""
    global _pool, _last_fail
    try:
        if _pool is not None:
            _pool.close()
    except Exception:
        pass
    _pool = None
    _last_fail = 0.0
