"""Data-access layer for the persistence schema. The ONLY module that issues SQL.

Every public function is a no-op / safe fallback when persistence is disabled
(``db.get_pool()`` is None), so callers never need to special-case it beyond
checking the return value.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import db


def _jsonb(value: Any):
    from psycopg.types.json import Jsonb  # lazy: optional dependency

    return Jsonb(value if value is not None else {})


# Finding.to_dict() keys -> findings columns (column name, dict key).
_FINDING_COLS = [
    ("vuln", "vuln"), ("cwe", "cwe"), ("severity", "severity"), ("title", "title"),
    ("file", "file"), ("line", "line"), ("col", "column"), ("sink", "sink"),
    ("source", "source"), ("param", "param"), ("method", "method"),
    ("function", "function"), ("framework", "framework"), ("rule", "rule"),
    ("code", "code"), ("message", "message"), ("how_in", "how_in"),
    ("impact", "impact"), ("owner", "owner"), ("action", "action"),
]


def save_scan(result: Dict, *, target: str = "", scan_type: str = "sample",
              duration_ms: Optional[int] = None, status: str = "completed",
              error: Optional[str] = None) -> Optional[int]:
    """Persist a scan result and its findings; also writes a scan.created audit
    row. Returns the new scan id, or None if persistence is off / it failed."""
    pool = db.get_pool()
    if pool is None:
        return None
    try:
        findings = result.get("findings", []) or []
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO scans
                       (target, display_root, scan_type, frameworks, files_scanned,
                        counts, status, duration_ms, error)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                    (target, result.get("root", ""), scan_type,
                     _jsonb(result.get("frameworks", {})),
                     int(result.get("files_scanned", 0) or 0),
                     _jsonb(result.get("counts", {})), status, duration_ms, error),
                )
                scan_id = cur.fetchone()[0]

                cols = ["scan_id", "idx", "exposure", "fix"] + [c for c, _ in _FINDING_COLS]
                placeholders = ",".join(["%s"] * len(cols))
                sql = f"INSERT INTO findings ({','.join(cols)}) VALUES ({placeholders})"
                rows = []
                for i, f in enumerate(findings):
                    row = [scan_id, i, _jsonb(f.get("exposure", [])), _jsonb(f.get("fix", []))]
                    row += [f.get(key) for _, key in _FINDING_COLS]
                    rows.append(row)
                if rows:
                    cur.executemany(sql, rows)

                cur.execute(
                    """INSERT INTO activity_log (scan_id, entity_type, entity_id, action, actor, details)
                       VALUES (%s,'scan',%s,%s,'system',%s)""",
                    (scan_id, scan_id, "scan.created" if status == "completed" else "scan.failed",
                     _jsonb({"findings": len(findings), "root": result.get("root", ""),
                             "scan_type": scan_type, "error": error})),
                )
            conn.commit()
        return scan_id
    except Exception as exc:
        print(f"[sbvf.store] save_scan failed: {exc}")
        return None


def list_scans(limit: int = 50, offset: int = 0) -> List[Dict]:
    """Most-recent-first scan summaries with a findings count."""
    pool = db.get_pool()
    if pool is None:
        return []
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT s.id, s.created_at, s.display_root, s.scan_type, s.frameworks,
                          s.files_scanned, s.counts, s.status, s.duration_ms,
                          COUNT(f.id) AS findings_count
                   FROM scans s LEFT JOIN findings f ON f.scan_id = s.id
                   GROUP BY s.id ORDER BY s.created_at DESC LIMIT %s OFFSET %s""",
                (limit, offset),
            )
            return [_scan_row(r) for r in cur.fetchall()]
    except Exception as exc:
        print(f"[sbvf.store] list_scans failed: {exc}")
        return []


def get_scan(scan_id: int) -> Optional[Dict]:
    """Full scan with its findings, or None if missing / persistence off."""
    pool = db.get_pool()
    if pool is None:
        return None
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT id, created_at, display_root, scan_type, frameworks,
                          files_scanned, counts, status, duration_ms, error
                   FROM scans WHERE id = %s""", (scan_id,))
            row = cur.fetchone()
            if row is None:
                return None
            scan = {
                "id": row[0], "created_at": row[1].isoformat(), "root": row[2],
                "scan_type": row[3], "frameworks": row[4], "files_scanned": row[5],
                "counts": row[6], "status": row[7], "duration_ms": row[8], "error": row[9],
            }
            cur.execute(
                """SELECT vuln, cwe, severity, title, file, line, col, sink, source,
                          param, method, function, framework, rule, code, message,
                          how_in, impact, owner, action, exposure, fix
                   FROM findings WHERE scan_id = %s ORDER BY idx""", (scan_id,))
            names = ["vuln", "cwe", "severity", "title", "file", "line", "column", "sink",
                     "source", "param", "method", "function", "framework", "rule", "code",
                     "message", "how_in", "impact", "owner", "action", "exposure", "fix"]
            findings = []
            for fr in cur.fetchall():
                d = dict(zip(names, fr))
                d["location"] = f"{d['file']}:{d['line']}" if d.get("file") else ""
                findings.append(d)
            scan["findings"] = findings
            return scan
    except Exception as exc:
        print(f"[sbvf.store] get_scan failed: {exc}")
        return None


def delete_scan(scan_id: int) -> bool:
    """Delete a scan (findings cascade). Logs scan.deleted. Returns success."""
    pool = db.get_pool()
    if pool is None:
        return False
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM scans WHERE id = %s", (scan_id,))
                deleted = cur.rowcount > 0
                if deleted:
                    # scan row is gone; log with scan_id NULL, id in details.
                    cur.execute(
                        """INSERT INTO activity_log (entity_type, entity_id, action, actor, details)
                           VALUES ('scan',%s,'scan.deleted','ui',%s)""",
                        (scan_id, _jsonb({"id": scan_id})))
            conn.commit()
        return deleted
    except Exception as exc:
        print(f"[sbvf.store] delete_scan failed: {exc}")
        return False


def log_activity(action: str, *, scan_id: Optional[int] = None, entity_type: str = "system",
                 entity_id: Optional[int] = None, actor: str = "system",
                 details: Optional[Dict] = None) -> bool:
    """Append an audit row. Safe no-op when persistence is off."""
    pool = db.get_pool()
    if pool is None:
        return False
    try:
        with pool.connection() as conn:
            conn.execute(
                """INSERT INTO activity_log (scan_id, entity_type, entity_id, action, actor, details)
                   VALUES (%s,%s,%s,%s,%s,%s)""",
                (scan_id, entity_type, entity_id, action, actor, _jsonb(details or {})))
            conn.commit()
        return True
    except Exception as exc:
        print(f"[sbvf.store] log_activity failed: {exc}")
        return False


def list_activity(limit: int = 100, scan_id: Optional[int] = None) -> List[Dict]:
    """Most-recent-first audit entries, optionally scoped to one scan."""
    pool = db.get_pool()
    if pool is None:
        return []
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            if scan_id is None:
                cur.execute(
                    """SELECT id, created_at, scan_id, entity_type, entity_id, action, actor, details
                       FROM activity_log ORDER BY created_at DESC LIMIT %s""", (limit,))
            else:
                cur.execute(
                    """SELECT id, created_at, scan_id, entity_type, entity_id, action, actor, details
                       FROM activity_log WHERE scan_id = %s ORDER BY created_at DESC LIMIT %s""",
                    (scan_id, limit))
            cols = ["id", "created_at", "scan_id", "entity_type", "entity_id", "action", "actor", "details"]
            out = []
            for r in cur.fetchall():
                d = dict(zip(cols, r))
                d["created_at"] = d["created_at"].isoformat()
                out.append(d)
            return out
    except Exception as exc:
        print(f"[sbvf.store] list_activity failed: {exc}")
        return []


def _scan_row(r) -> Dict:
    return {
        "id": r[0], "created_at": r[1].isoformat(), "root": r[2], "scan_type": r[3],
        "frameworks": r[4], "files_scanned": r[5], "counts": r[6], "status": r[7],
        "duration_ms": r[8], "findings_count": r[9],
    }
