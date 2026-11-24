"""Connection handling for the optional PostgreSQL persistence layer.

Persistence is entirely optional: if ``DATABASE_URL`` is not set, or psycopg is
not installed, or the database is unreachable, :func:`get_pool` returns ``None``
and the rest of the application runs exactly as before (scans still stream, they
are simply not stored). Nothing here is imported by the stdlib-only core scanner.
"""
from __future__ import annotations

import os
import threading
from typing import Optional

_pool = None
_init_done = False
_lock = threading.Lock()


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

    Safe to call repeatedly; the pool is created once. Any failure (missing
    driver, bad URL, server down) is swallowed and reported as None so callers
    degrade gracefully.
    """
    global _pool, _init_done
    if _init_done:
        return _pool
    with _lock:
        if _init_done:
            return _pool
        _init_done = True
        url = database_url()
        if not url:
            return None
        try:
            from psycopg_pool import ConnectionPool  # lazy: optional dependency

            _pool = ConnectionPool(
                conninfo=url, min_size=1, max_size=int(os.environ.get("SBVF_DB_POOL", "5")),
                kwargs={"autocommit": False}, open=True, timeout=10,
            )
            # Validate connectivity once up front.
            with _pool.connection() as conn:
                conn.execute("SELECT 1")
            return _pool
        except Exception as exc:  # driver missing / server unreachable
            print(f"[sbvf.store] persistence disabled: {exc}")
            _pool = None
            return None


def reset_for_tests() -> None:
    """Drop the cached pool so a test can reconfigure the environment."""
    global _pool, _init_done
    try:
        if _pool is not None:
            _pool.close()
    except Exception:
        pass
    _pool = None
    _init_done = False
