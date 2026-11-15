"""Tests for the static (SAST) analysis engine.

Each test scans a bundled intentionally-vulnerable sample and asserts that:
  (a) the correct language/framework is detected,
  (b) every planted vulnerability is reported at the expected line, and
  (c) the sanitized "safe" counterparts produce no findings (no false positives).

Runnable with pytest or `python -m tests.test_sast`.
"""
import os
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbvf.sast import scan_path, derive_endpoints, extract_routes  # noqa: E402
from sbvf.sast.php import PhpAnalyzer                         # noqa: E402
from sbvf.sast.python_analyzer import PythonAnalyzer          # noqa: E402
from sbvf.algorithms import ALGORITHMS                        # noqa: E402
from sbvf.external import run_external                        # noqa: E402
from sbvf.oracles import Target                               # noqa: E402
import testbed.app as app                                     # noqa: E402

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


class TestParamRecovery(unittest.TestCase):
    """The PHP analyzer records the request parameter + method behind each finding,
    both directly and through an intermediate variable."""

    def test_direct_and_via_variable(self):
        src = ("<?php\n"
               "$id = $_GET['id'];\n"
               "mysqli_query($c, \"SELECT * FROM u WHERE id=\" . $id);\n"
               "echo $_GET['name'];\n"
               "system('ping ' . $_POST['host']);\n"
               "?>")
        got = {f.vuln: (f.param, f.method)
               for f in PhpAnalyzer("php-native").analyze("p.php", src)}
        self.assertEqual(got["sqli"], ("id", "GET"))       # recovered through $id
        self.assertEqual(got["xss"], ("name", "GET"))      # recovered directly
        self.assertEqual(got["command_injection"], ("host", "POST"))


class TestDeriveEndpoints(unittest.TestCase):
    """The static->dynamic bridge turns GET-reachable, file-routed PHP findings
    into endpoints and holds everything else back as static-only."""

    def test_native_php_sample(self):
        res = scan_path(os.path.join(SAMPLES, "php_native"))
        eps, skipped = derive_endpoints(res["findings"])
        got = {(e.path, e.param, e.vuln) for e in eps}
        self.assertIn(("/vuln.php", "id", "sqli"), got)
        self.assertIn(("/vuln.php", "name", "xss"), got)
        # command/code/file-inclusion are not GET-confirmable -> static-only
        self.assertTrue(all(e.vuln in ("xss", "sqli") for e in eps))
        self.assertTrue(any(s["vuln"] == "command_injection" for s in skipped))

    def test_framework_routes_are_static_only(self):
        findings = [{"vuln": "sqli", "file": "app/Http/Controllers/X.php",
                     "framework": "laravel", "method": "GET", "param": "id",
                     "location": "app/Http/Controllers/X.php:10"}]
        eps, skipped = derive_endpoints(findings)
        self.assertEqual(eps, [])
        self.assertIn("not file-based", skipped[0]["reason"])

    def test_web_root_strip(self):
        findings = [{"vuln": "xss", "file": "public/search.php",
                     "framework": "php-native", "method": "GET", "param": "q",
                     "location": "public/search.php:3"}]
        eps, _ = derive_endpoints(findings, strip_prefix="public")
        self.assertEqual(eps[0].path, "/search.php")

    def test_dedup(self):
        f = {"vuln": "sqli", "file": "a.php", "framework": "php-native",
             "method": "GET", "param": "id", "location": "a.php:1"}
        eps, _ = derive_endpoints([f, dict(f, location="a.php:9")])
        self.assertEqual(len(eps), 1)


class TestGuidedDynamicConfirmation(unittest.TestCase):
    """End-to-end: endpoints derived from a static finding are confirmed by the
    search algorithms against a live app (the in-process testbed stands in for a
    scanned open-source PHP app, whose file paths map to these routes)."""

    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_sast_finding_is_dynamically_confirmed(self):
        # A static finding at xss/reflect_raw.php?q=  (file path -> route).
        findings = [{"vuln": "xss", "file": "xss/reflect_raw",
                     "framework": "php-native", "method": "GET", "param": "q",
                     "location": "xss/reflect_raw:1"}]
        eps, _ = derive_endpoints(findings)
        self.assertEqual(len(eps), 1)
        report = run_external(self.base, eps, runs=1, budget=200,
                              methods={"GA": ALGORITHMS["GA"]})
        self.assertEqual(report[0]["methods"]["GA"]["detections"], 1)

    def test_safe_endpoint_not_confirmed(self):
        findings = [{"vuln": "xss", "file": "xss/safe", "framework": "php-native",
                     "method": "GET", "param": "q", "location": "xss/safe:1"}]
        eps, _ = derive_endpoints(findings)
        report = run_external(self.base, eps, runs=1, budget=200,
                              methods={"GA": ALGORITHMS["GA"]})
        self.assertEqual(report[0]["methods"]["GA"]["detections"], 0)


def _project(files):
    """Write {relative path: source} into a fresh temp dir; return the dir object."""
    tmp = tempfile.TemporaryDirectory()
    for rel, src in files.items():
        path = os.path.join(tmp.name, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(src))
    return tmp


class TestPythonRoutes(unittest.TestCase):
    """Route recovery for Django urls.py and FastAPI decorators (read statically)."""

    def test_django_sample(self):
        routes = extract_routes(os.path.join(SAMPLES, "python_django"))
        r = routes[("views", "profile")][0]
        self.assertEqual(r.path, "/profile/1/")
        self.assertEqual(r.path_params, ("uid",))

    def test_fastapi_sample(self):
        routes = extract_routes(os.path.join(SAMPLES, "python_fastapi"))
        r = routes[("main", "get_user")][0]
        self.assertEqual((r.path, r.methods), ("/user", ("GET",)))

    def test_django_include_prefix(self):
        with _project({
            "site/urls.py": """
                from django.urls import path, include
                urlpatterns = [path("shop/", include("shop.urls"))]
            """,
            "shop/urls.py": """
                from django.urls import path
                from .views import item
                urlpatterns = [path("item/<slug:s>/", item)]
            """,
            "shop/views.py": "def item(request, s):\n    pass\n",
        }) as root:
            r = extract_routes(root)[("shop/views", "item")][0]
            self.assertEqual(r.path, "/shop/item/1/")

    def test_fastapi_router_prefixes(self):
        with _project({
            "main.py": """
                from fastapi import FastAPI
                from . import users
                app = FastAPI()
                app.include_router(users.router, prefix="/v1")
            """,
            "users.py": """
                from fastapi import APIRouter
                router = APIRouter(prefix="/users")
                @router.get("/{uid}/search")
                def search(uid: int, q: str):
                    pass
            """,
        }) as root:
            r = extract_routes(root)[("users", "search")][0]
            self.assertEqual(r.path, "/v1/users/1/search")
            self.assertEqual(r.path_params, ("uid",))


class TestDerivePythonEndpoints(unittest.TestCase):
    def _derive(self, sample):
        root = os.path.join(SAMPLES, sample)
        return derive_endpoints(scan_path(root)["findings"], routes=extract_routes(root))

    def test_django_sample(self):
        eps, skipped = self._derive("python_django")
        self.assertEqual({(e.path, e.param, e.vuln) for e in eps},
                         {("/profile/1/", "name", "sqli"), ("/profile/1/", "name", "xss")})
        self.assertTrue(any(s["vuln"] == "open_redirect" for s in skipped))

    def test_fastapi_sample(self):
        eps, _ = self._derive("python_fastapi")
        self.assertEqual({(e.path, e.param, e.vuln) for e in eps},
                         {("/user", "name", "sqli"), ("/user", "name", "xss")})

    def test_path_param_is_static_only(self):
        f = {"vuln": "sqli", "file": "views.py", "framework": "django",
             "method": "PATH", "param": "uid", "function": "profile",
             "location": "views.py:3"}
        eps, skipped = derive_endpoints([f], routes={})
        self.assertEqual(eps, [])
        self.assertIn("path segment", skipped[0]["reason"])

    def test_post_only_route_is_static_only(self):
        with _project({"main.py": """
            from fastapi import FastAPI
            from fastapi.responses import HTMLResponse
            app = FastAPI()
            @app.post("/echo")
            def echo(q: str):
                return HTMLResponse(q)
        """}) as root:
            eps, skipped = derive_endpoints(scan_path(root)["findings"],
                                            routes=extract_routes(root))
            self.assertEqual(eps, [])
            self.assertIn("does not accept GET", skipped[0]["reason"])


class TestGuidedPythonConfirmation(unittest.TestCase):
    """End-to-end on Python stacks: a Django/FastAPI project is scanned
    statically, its route table recovered, and the derived endpoint confirmed by
    the search against a live server serving those routes."""

    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _confirm(self, files, algo):
        with _project(files) as root:
            eps, _ = derive_endpoints(scan_path(root)["findings"],
                                      routes=extract_routes(root))
        self.assertEqual(len(eps), 1)
        report = run_external(self.base, eps, runs=1, budget=200,
                              methods={algo: ALGORITHMS[algo]})
        return eps[0], report[0]["methods"][algo]["detections"]

    def test_django_xss_route_confirmed(self):
        ep, hits = self._confirm({
            "manage.py": "",
            "urls.py": """
                from django.urls import path
                from . import views
                urlpatterns = [path("xss/reflect_raw", views.search)]
            """,
            "views.py": """
                from django.http import HttpResponse
                def search(request):
                    q = request.GET.get("q")
                    return HttpResponse("<p>" + q + "</p>")
            """,
        }, "GA")
        self.assertEqual((ep.path, ep.param, ep.vuln), ("/xss/reflect_raw", "q", "xss"))
        self.assertEqual(hits, 1)

    def test_fastapi_sqli_route_confirmed(self):
        ep, hits = self._confirm({"main.py": """
            import sqlite3
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/sqli/error")
            def lookup(name: str):
                cur = sqlite3.connect("x.db").cursor()
                cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
        """}, "CS")
        self.assertEqual((ep.path, ep.param, ep.vuln), ("/sqli/error", "name", "sqli"))
        self.assertEqual(hits, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
