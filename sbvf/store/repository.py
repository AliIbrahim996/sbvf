"""Data-access layer for the persistence schema. The ONLY module that issues SQL.

Every public function is a no-op / safe fallback when persistence is disabled
(``db.get_pool()`` is None), so callers never need to special-case it beyond
checking the return value.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from . import db

_SEARCH_WORD = re.compile(r"[A-Za-z0-9]+")


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


# ----------------------------- AI-agents layer -----------------------------
# All no-ops when persistence is off; written only by sbvf/agents/.

def finding_ids(scan_id: int) -> Dict[int, int]:
    """Map each finding's position (idx) to its database id, for FK linkage."""
    pool = db.get_pool()
    if pool is None:
        return {}
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT idx, id FROM findings WHERE scan_id = %s", (scan_id,))
            return {int(idx): int(fid) for idx, fid in cur.fetchall()}
    except Exception as exc:
        print(f"[sbvf.store] finding_ids failed: {exc}")
        return {}


def save_agent_run(scan_id: int, agent: str, provider: str, model: str, *,
                   status: str = "completed", duration_ms: Optional[int] = None,
                   error: Optional[str] = None, details: Optional[Dict] = None,
                   ) -> Optional[int]:
    """Record one agent invocation and log it to the audit trail."""
    pool = db.get_pool()
    if pool is None:
        return None
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO agent_runs
                       (scan_id, agent, provider, model, status, duration_ms, error, details)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                    (scan_id, agent, provider, model, status, duration_ms, error,
                     _jsonb(details or {})),
                )
                run_id = cur.fetchone()[0]
                cur.execute(
                    """INSERT INTO activity_log (scan_id, entity_type, entity_id, action, actor, details)
                       VALUES (%s,'agent',%s,%s,%s,%s)""",
                    (scan_id, run_id,
                     "agent.run.finished" if status == "completed" else "agent.run.failed",
                     f"agent:{agent}",
                     _jsonb({"provider": provider, "model": model, "error": error,
                             **(details or {})})),
                )
            conn.commit()
        return run_id
    except Exception as exc:
        print(f"[sbvf.store] save_agent_run failed: {exc}")
        return None


def save_assessment(scan_id: int, finding_idx: int, *, finding_id: Optional[int] = None,
                    provider: str = "", model: str = "",
                    triage: Optional[Dict] = None, remediation: Optional[Dict] = None,
                    ) -> Optional[int]:
    """Persist a per-finding assessment (triage and/or remediation). No-op if both
    are None or persistence is off."""
    if triage is None and remediation is None:
        return None
    pool = db.get_pool()
    if pool is None:
        return None
    agents = []
    is_fp = conf = rationale = None
    rem_summary = rem = None
    if triage is not None:
        agents.append("triage")
        is_fp = bool(triage.get("is_false_positive", False))
        conf = triage.get("confidence")
        rationale = triage.get("rationale")
    if remediation is not None:
        agents.append("remediation")
        rem_summary = remediation.get("summary")
        rem = remediation.get("remediation")
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO finding_assessments
                       (scan_id, finding_id, finding_idx, provider, model, is_false_positive,
                        confidence, rationale, remediation_summary, remediation, agents)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                    (scan_id, finding_id, finding_idx, provider, model, is_fp, conf,
                     rationale, rem_summary, rem, _jsonb(agents)),
                )
                assessment_id = cur.fetchone()[0]
                cur.execute(
                    """INSERT INTO activity_log (scan_id, entity_type, entity_id, action, actor, details)
                       VALUES (%s,'finding',%s,'finding.assessed',%s,%s)""",
                    (scan_id, finding_id, f"agent:{'+'.join(agents)}",
                     _jsonb({"finding_idx": finding_idx, "agents": agents})),
                )
            conn.commit()
        return assessment_id
    except Exception as exc:
        print(f"[sbvf.store] save_assessment failed: {exc}")
        return None


def save_prioritization(scan_id: int, *, provider: str = "", model: str = "",
                        summary: str = "", ranking: Optional[List] = None) -> Optional[int]:
    """Persist a scan-level risk prioritization."""
    pool = db.get_pool()
    if pool is None:
        return None
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                """INSERT INTO scan_prioritizations (scan_id, provider, model, summary, ranking)
                   VALUES (%s,%s,%s,%s,%s) RETURNING id""",
                (scan_id, provider, model, summary, _jsonb(ranking or [])),
            )
            pid = cur.fetchone()[0]
            conn.commit()
        return pid
    except Exception as exc:
        print(f"[sbvf.store] save_prioritization failed: {exc}")
        return None


def get_assessments(scan_id: int) -> List[Dict]:
    """Most-recent assessment per finding (by finding_idx)."""
    pool = db.get_pool()
    if pool is None:
        return []
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT DISTINCT ON (finding_idx)
                          finding_idx, is_false_positive, confidence, rationale,
                          remediation_summary, remediation, provider, model, agents, created_at
                   FROM finding_assessments WHERE scan_id = %s
                   ORDER BY finding_idx, created_at DESC""", (scan_id,))
            cols = ["finding_idx", "is_false_positive", "confidence", "rationale",
                    "remediation_summary", "remediation", "provider", "model", "agents",
                    "created_at"]
            out = []
            for r in cur.fetchall():
                d = dict(zip(cols, r))
                d["created_at"] = d["created_at"].isoformat()
                out.append(d)
            return out
    except Exception as exc:
        print(f"[sbvf.store] get_assessments failed: {exc}")
        return []


def get_prioritization(scan_id: int) -> Optional[Dict]:
    """Most-recent scan prioritization, or None."""
    pool = db.get_pool()
    if pool is None:
        return None
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT summary, ranking, provider, model, created_at
                   FROM scan_prioritizations WHERE scan_id = %s
                   ORDER BY created_at DESC LIMIT 1""", (scan_id,))
            row = cur.fetchone()
            if row is None:
                return None
            return {"summary": row[0], "ranking": row[1], "provider": row[2],
                    "model": row[3], "created_at": row[4].isoformat()}
    except Exception as exc:
        print(f"[sbvf.store] get_prioritization failed: {exc}")
        return None


def get_ai(scan_id: int) -> Dict:
    """Combined AI output for a scan: assessments + prioritization."""
    return {"assessments": get_assessments(scan_id),
            "prioritization": get_prioritization(scan_id)}


# ------------------------------- Q&A layer -------------------------------

def search_findings(query: str, limit: int = 20) -> List[Dict]:
    """Findings whose text matches any query term (ILIKE), newest first.

    With no usable terms, returns the most recent findings as general context.
    """
    pool = db.get_pool()
    if pool is None:
        return []
    terms = [w.lower() for w in _SEARCH_WORD.findall(query or "") if len(w) > 2][:8]
    cols = ["title", "message", "file", "vuln", "cwe"]
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            sql = ("SELECT scan_id, title, cwe, severity, file, line, vuln, message "
                   "FROM findings")
            params: List[Any] = []
            if terms:
                ors = []
                for t in terms:
                    ors.append("(" + " OR ".join(f"{c} ILIKE %s" for c in cols) + ")")
                    params += [f"%{t}%"] * len(cols)
                sql += " WHERE " + " OR ".join(ors)
            sql += " ORDER BY id DESC LIMIT %s"
            params.append(limit)
            cur.execute(sql, params)
            names = ["scan_id", "title", "cwe", "severity", "file", "line", "vuln", "message"]
            out = []
            for r in cur.fetchall():
                d = dict(zip(names, r))
                d["location"] = f"{d['file']}:{d['line']}" if d.get("file") else ""
                out.append(d)
            return out
    except Exception as exc:
        print(f"[sbvf.store] search_findings failed: {exc}")
        return []


def save_chat_message(role: str, content: str, *, scan_id: Optional[int] = None,
                      provider: str = "", model: str = "",
                      details: Optional[Dict] = None) -> Optional[int]:
    """Persist one chat turn; the assistant turn also logs a qa.answered audit row."""
    pool = db.get_pool()
    if pool is None:
        return None
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO chat_messages (scan_id, role, content, provider, model, details)
                       VALUES (%s,%s,%s,%s,%s,%s) RETURNING id""",
                    (scan_id, role, content, provider, model, _jsonb(details or {})),
                )
                msg_id = cur.fetchone()[0]
                if role == "assistant":
                    cur.execute(
                        """INSERT INTO activity_log (scan_id, entity_type, entity_id, action, actor, details)
                           VALUES (%s,'chat',%s,'qa.answered',%s,%s)""",
                        (scan_id, msg_id, f"agent:qa:{provider}" if provider else "agent:qa",
                         _jsonb({"model": model})),
                    )
            conn.commit()
        return msg_id
    except Exception as exc:
        print(f"[sbvf.store] save_chat_message failed: {exc}")
        return None


def list_chat(limit: int = 50, scan_id: Optional[int] = None) -> List[Dict]:
    """Chat turns in chronological order. scan_id=None returns the global thread
    (messages not tied to a specific scan)."""
    pool = db.get_pool()
    if pool is None:
        return []
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            if scan_id is None:
                cur.execute(
                    """SELECT id, created_at, scan_id, role, content, provider, model, details
                       FROM chat_messages WHERE scan_id IS NULL
                       ORDER BY id DESC LIMIT %s""", (limit,))
            else:
                cur.execute(
                    """SELECT id, created_at, scan_id, role, content, provider, model, details
                       FROM chat_messages WHERE scan_id = %s
                       ORDER BY id DESC LIMIT %s""", (scan_id, limit))
            names = ["id", "created_at", "scan_id", "role", "content", "provider", "model", "details"]
            out = []
            for r in cur.fetchall():
                d = dict(zip(names, r))
                d["created_at"] = d["created_at"].isoformat()
                out.append(d)
            out.reverse()  # chronological (oldest first) for display
            return out
    except Exception as exc:
        print(f"[sbvf.store] list_chat failed: {exc}")
        return []
