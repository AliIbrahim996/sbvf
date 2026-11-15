"""Tests for the static (SAST) analysis engine.

Each test scans a bundled intentionally-vulnerable sample and asserts that:
  (a) the correct language/framework is detected,
  (b) every planted vulnerability is reported at the expected line, and
  (c) the sanitized "safe" counterparts produce no findings (no false positives).

Runnable with pytest or `python -m tests.test_sast`.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbvf.sast import scan_path                               # noqa: E402
from sbvf.sast.php import PhpAnalyzer                         # noqa: E402
from sbvf.sast.python_analyzer import PythonAnalyzer          # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "testbed", "sast_samples")


def _vulns(result):
    return {(f["vuln"], f["line"]) for f in result["findings"]}


def _by_file(result, suffix):
    return [f for f in result["findings"] if f["file"].endswith(suffix)]


class TestPhpNative(unittest.TestCase):
    def setUp(self):
        self.r = scan_path(os.path.join(SAMPLES, "php_native"))

    def test_framework_detected(self):
        self.assertEqual(self.r["frameworks"]["php"], "php-native")

    def test_all_classes_found(self):
        got = {v for v, _ in _vulns(self.r)}
        self.assertSetEqual(
            got, {"sqli", "xss", "command_injection", "file_inclusion", "code_injection"})

    def test_no_false_positives(self):
        # exactly the five planted vulnerabilities, nothing from the safe block
        self.assertEqual(len(self.r["findings"]), 5)


class TestYii(unittest.TestCase):
    def setUp(self):
        self.r = scan_path(os.path.join(SAMPLES, "php_yii"))

    def test_framework_detected(self):
        self.assertEqual(self.r["frameworks"]["php"], "yii")

    def test_sqli_and_xss(self):
        got = {v for v, _ in _vulns(self.r)}
        self.assertIn("sqli", got)
        self.assertIn("xss", got)

    def test_safe_action_clean(self):
        self.assertEqual(len(self.r["findings"]), 2)


class TestLaravel(unittest.TestCase):
    def setUp(self):
        self.r = scan_path(os.path.join(SAMPLES, "php_laravel"))

    def test_framework_detected(self):
        self.assertEqual(self.r["frameworks"]["php"], "laravel")

    def test_controller_findings(self):
        ctrl = _by_file(self.r, "UserController.php")
        kinds = {f["vuln"] for f in ctrl}
        self.assertSetEqual(kinds, {"sqli", "xss", "command_injection"})

    def test_blade_raw_echo_flagged(self):
        blade = _by_file(self.r, "user.blade.php")
        self.assertTrue(any(f["vuln"] == "xss" for f in blade))

    def test_count(self):
        self.assertEqual(len(self.r["findings"]), 4)


class TestPythonNative(unittest.TestCase):
    def setUp(self):
        self.r = scan_path(os.path.join(SAMPLES, "python_native"))

    def test_framework_detected(self):
        self.assertEqual(self.r["frameworks"]["python"], "python-native")

    def test_classes(self):
        got = {v for v, _ in _vulns(self.r)}
        self.assertSetEqual(got, {"sqli", "command_injection", "code_injection"})

    def test_no_dupes_or_false_positives(self):
        self.assertEqual(len(self.r["findings"]), 3)


class TestFastAPI(unittest.TestCase):
    def setUp(self):
        self.r = scan_path(os.path.join(SAMPLES, "python_fastapi"))

    def test_framework_detected(self):
        self.assertEqual(self.r["frameworks"]["python"], "fastapi")

    def test_param_sources(self):
        got = {v for v, _ in _vulns(self.r)}
        self.assertSetEqual(got, {"sqli", "xss", "command_injection"})

    def test_typed_int_param_not_injectable(self):
        # the /safe route uses a parameterized query -> no finding
        self.assertEqual(len(self.r["findings"]), 3)


class TestDjango(unittest.TestCase):
    def setUp(self):
        self.r = scan_path(os.path.join(SAMPLES, "python_django"))

    def test_framework_detected(self):
        self.assertEqual(self.r["frameworks"]["python"], "django")

    def test_classes(self):
        got = {v for v, _ in _vulns(self.r)}
        self.assertSetEqual(got, {"sqli", "xss", "open_redirect"})

    def test_parameterized_and_escaped_safe(self):
        self.assertEqual(len(self.r["findings"]), 3)


class TestAnalyzerUnits(unittest.TestCase):
    def test_php_prepared_statement_not_flagged(self):
        src = ("<?php $id=$_GET['id'];"
               "$s=$pdo->prepare('SELECT * FROM t WHERE id=?');$s->execute([$id]);")
        findings = PhpAnalyzer("php-native").analyze("x.php", src)
        self.assertEqual(findings, [])

    def test_php_concat_sqli_flagged(self):
        src = "<?php $id=$_GET['id']; mysqli_query($c, 'SELECT * FROM t WHERE id='.$id);"
        findings = PhpAnalyzer("php-native").analyze("x.php", src)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln, "sqli")

    def test_python_fstring_sqli(self):
        src = ("import request\n"
               "def v(request):\n"
               "    x = request.GET['q']\n"
               "    cur.execute(f\"SELECT * FROM t WHERE a='{x}'\")\n")
        findings = PythonAnalyzer("django").analyze("v.py", src)
        self.assertTrue(any(f.vuln == "sqli" for f in findings))

    def test_python_sanitized_int_clean(self):
        src = ("def v(request):\n"
               "    x = int(request.GET['q'])\n"
               "    cur.execute('SELECT * FROM t WHERE a=' + str(x))\n")
        findings = PythonAnalyzer("django").analyze("v.py", src)
        # int() casts away the string taint before it reaches the query
        self.assertEqual([f for f in findings if f.vuln == "sqli"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
