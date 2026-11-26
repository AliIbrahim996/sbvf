"""Round-trip tests for the persistence layer.

These require a reachable PostgreSQL (via DATABASE_URL) and psycopg installed;
they are skipped otherwise, so the suite stays green on the stdlib-only core.
Run against the compose DB, e.g.:
    DATABASE_URL=postgresql://sbvf:sbvf@localhost:5432/sbvf py -3.12 -m unittest tests.test_store
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbvf import store                                   # noqa: E402

_HAS_DB = store.db.is_enabled()
try:
    import psycopg  # noqa: F401
    _HAS_PSYCOPG = True
except Exception:
    _HAS_PSYCOPG = False


def _sample_result():
    return {
        "root": "testbed/sast_samples/php_native",
        "frameworks": {"php": "php-native", "python": "", "node": ""},
        "files_scanned": 1,
        "counts": {"by_vuln": {"sqli": 1}, "by_severity": {"high": 1, "medium": 0, "low": 0}},
        "findings": [{
            "vuln": "sqli", "cwe": "CWE-89", "severity": "high", "title": "SQL Injection",
            "file": "vuln.php", "line": 9, "column": 0, "sink": "mysqli_query",
            "source": "$_GET['id']", "param": "id", "method": "GET", "function": "",
            "framework": "php-native", "rule": "", "code": "$res = mysqli_query($c,$q);",
            "message": "tainted input reaches sink", "how_in": "GET id flows to mysqli_query",
            "impact": "DB read/write", "owner": "Backend", "action": "Fix this sprint",
            "exposure": ["Data", "Accounts"], "fix": ["Use prepared statements"],
            "location": "vuln.php:9",
        }],
    }


@unittest.skipUnless(_HAS_DB and _HAS_PSYCOPG,
                     "needs DATABASE_URL + psycopg (persistence layer)")
class TestStoreRoundTrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert store.migrate.init(), "schema migration failed"

    def test_save_get_list_activity_delete(self):
        scan_id = store.repository.save_scan(
            _sample_result(), target="php_native", scan_type="sample", duration_ms=12)
        self.assertIsInstance(scan_id, int)

        scan = store.repository.get_scan(scan_id)
        self.assertIsNotNone(scan)
        self.assertEqual(scan["files_scanned"], 1)
        self.assertEqual(len(scan["findings"]), 1)
        f = scan["findings"][0]
        self.assertEqual((f["vuln"], f["cwe"], f["severity"]), ("sqli", "CWE-89", "high"))
        self.assertEqual(f["exposure"], ["Data", "Accounts"])
        self.assertEqual(f["fix"], ["Use prepared statements"])

        ids = [s["id"] for s in store.repository.list_scans(limit=100)]
        self.assertIn(scan_id, ids)

        acts = store.repository.list_activity(scan_id=scan_id)
        self.assertTrue(any(a["action"] == "scan.created" for a in acts))

        self.assertTrue(store.repository.delete_scan(scan_id))
        self.assertIsNone(store.repository.get_scan(scan_id))

    def test_empty_findings_scan(self):
        scan_id = store.repository.save_scan(
            {"root": "x", "frameworks": {}, "files_scanned": 0,
             "counts": {}, "findings": []}, scan_type="sample")
        self.assertIsInstance(scan_id, int)
        self.assertEqual(store.repository.get_scan(scan_id)["findings"], [])
        store.repository.delete_scan(scan_id)


@unittest.skipUnless(_HAS_DB and _HAS_PSYCOPG,
                     "needs DATABASE_URL + psycopg (persistence layer)")
class TestMultiUser(unittest.TestCase):
    """Accounts, sessions, and per-user scan scoping (multi-user basics)."""

    @classmethod
    def setUpClass(cls):
        assert store.migrate.init(), "schema migration failed"

    def _unique(self, base):
        import uuid
        return f"{base}-{uuid.uuid4().hex[:8]}"

    def test_create_user_first_is_admin_and_unique(self):
        name = self._unique("user")
        u = store.repository.create_user(name, "password123")
        self.assertIsNotNone(u)
        self.assertIn(u["role"], ("admin", "user"))   # first ever is admin; later 'user'
        self.assertIsNone(store.repository.create_user(name, "password123"))  # duplicate

    def test_verify_user(self):
        name = self._unique("login")
        store.repository.create_user(name, "password123")
        self.assertIsNotNone(store.repository.verify_user(name, "password123"))
        self.assertIsNone(store.repository.verify_user(name, "wrong-password"))
        self.assertIsNone(store.repository.verify_user("no-such-user", "password123"))

    def test_session_lifecycle(self):
        name = self._unique("sess")
        u = store.repository.create_user(name, "password123")
        token = store.repository.create_session(u["id"])
        self.assertTrue(token)
        got = store.repository.get_session_user(token)
        self.assertEqual(got["id"], u["id"])
        self.assertTrue(store.repository.delete_session(token))
        self.assertIsNone(store.repository.get_session_user(token))   # revoked

    def test_scan_ownership_isolation(self):
        a = store.repository.create_user(self._unique("owner-a"), "password123")
        b = store.repository.create_user(self._unique("owner-b"), "password123")
        sid = store.repository.save_scan(_sample_result(), target="x", owner_id=a["id"])
        self.assertIsInstance(sid, int)
        # owner A sees it; B does not; admin override does.
        self.assertIsNotNone(store.repository.get_scan(sid, owner_id=a["id"]))
        self.assertIsNone(store.repository.get_scan(sid, owner_id=b["id"]))
        self.assertIsNotNone(store.repository.get_scan(sid, owner_id=b["id"], is_admin=True))
        a_ids = [s["id"] for s in store.repository.list_scans(owner_id=a["id"])]
        b_ids = [s["id"] for s in store.repository.list_scans(owner_id=b["id"])]
        self.assertIn(sid, a_ids)
        self.assertNotIn(sid, b_ids)
        # B cannot delete A's scan; A can.
        self.assertFalse(store.repository.delete_scan(sid, owner_id=b["id"]))
        self.assertIsNotNone(store.repository.get_scan(sid, owner_id=a["id"]))
        self.assertTrue(store.repository.delete_scan(sid, owner_id=a["id"]))

    def test_unscoped_calls_still_see_all(self):
        # auth-off callers (no owner_id) keep single-user behaviour: see every scan.
        u = store.repository.create_user(self._unique("legacy"), "password123")
        sid = store.repository.save_scan(_sample_result(), target="x", owner_id=u["id"])
        self.assertIn(sid, [s["id"] for s in store.repository.list_scans(limit=200)])
        self.assertIsNotNone(store.repository.get_scan(sid))
        store.repository.delete_scan(sid)


class TestStoreDisabledSafe(unittest.TestCase):
    """With no DB the repository must degrade to safe no-ops (never raise)."""

    @unittest.skipIf(_HAS_DB, "DATABASE_URL is set; disabled-path test not applicable")
    def test_noops(self):
        self.assertEqual(store.repository.list_scans(), [])
        self.assertIsNone(store.repository.get_scan(1))
        self.assertIsNone(store.repository.save_scan({"findings": []}))
        self.assertFalse(store.repository.delete_scan(1))
        self.assertEqual(store.repository.list_activity(), [])

    @unittest.skipIf(_HAS_DB, "DATABASE_URL is set; disabled-path test not applicable")
    def test_auth_noops(self):
        self.assertEqual(store.repository.count_users(), 0)
        self.assertIsNone(store.repository.create_user("alice", "password123"))
        self.assertIsNone(store.repository.verify_user("alice", "password123"))
        self.assertIsNone(store.repository.create_session(1))
        self.assertIsNone(store.repository.get_session_user("tok"))
        self.assertFalse(store.repository.delete_session("tok"))
        self.assertFalse(store.auth.auth_enabled())    # off without a DB


if __name__ == "__main__":
    unittest.main(verbosity=2)
