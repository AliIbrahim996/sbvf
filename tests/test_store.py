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


class TestStoreDisabledSafe(unittest.TestCase):
    """With no DB the repository must degrade to safe no-ops (never raise)."""

    @unittest.skipIf(_HAS_DB, "DATABASE_URL is set; disabled-path test not applicable")
    def test_noops(self):
        self.assertEqual(store.repository.list_scans(), [])
        self.assertIsNone(store.repository.get_scan(1))
        self.assertIsNone(store.repository.save_scan({"findings": []}))
        self.assertFalse(store.repository.delete_scan(1))
        self.assertEqual(store.repository.list_activity(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
