"""Optional PostgreSQL persistence for SBVF scans, findings and an audit log.

Isolated from the stdlib-only core scanner: importing this package pulls in no
third-party dependency until a function actually connects (psycopg is imported
lazily). When ``DATABASE_URL`` is unset or the driver/server is unavailable,
every repository call is a safe no-op, so the scanner runs unchanged.
"""
from __future__ import annotations

from . import db, migrate, repository, auth

__all__ = ["db", "migrate", "repository", "auth", "is_enabled"]


def is_enabled() -> bool:
    return db.is_enabled()
