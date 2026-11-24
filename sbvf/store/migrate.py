"""Apply the persistence schema idempotently. No-op when persistence is off."""
from __future__ import annotations

import os

from . import db

_SCHEMA = os.path.join(os.path.dirname(__file__), "schema.sql")


def init() -> bool:
    """Create tables if needed. Returns True if the schema was applied, else False
    (persistence disabled or unreachable). Never raises."""
    pool = db.get_pool()
    if pool is None:
        return False
    try:
        with open(_SCHEMA, "r", encoding="utf-8") as fh:
            ddl = fh.read()
        with pool.connection() as conn:
            conn.execute(ddl)
            conn.commit()
        print("[sbvf.store] schema ready")
        return True
    except Exception as exc:
        print(f"[sbvf.store] migration failed: {exc}")
        return False
