"""Tests for the static (SAST) analysis engine.

Each test scans a bundled intentionally-vulnerable sample and asserts that:
  (a) the correct language/framework is detected,
  (b) every planted vulnerability is reported at the expected line, and
  (c) the sanitized "safe" counterparts produce no findings (no false positives).

Runnable with pytest or `python -m tests.test_sast`.
"""
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import urllib.parse                                          # noqa: E402
from http.server import BaseHTTPRequestHandler               # noqa: E402

from sbvf.sast import scan_path, derive_endpoints, extract_routes  # noqa: E402
from sbvf.sast.php import PhpAnalyzer                         # noqa: E402
from sbvf.sast.python_analyzer import PythonAnalyzer          # noqa: E402
from sbvf.algorithms import ALGORITHMS                        # noqa: E402
from sbvf.external import run_external, ExternalEndpoint      # noqa: E402
from sbvf.oracles import Target, Oracle                       # noqa: E402
from sbvf.fitness import CMDI_MARKER                          # noqa: E402
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
        self.assertIn(("/vuln.php", "host", "command_injection"), got)   # now confirmable
        # code injection / file inclusion are not dynamically confirmable -> static-only
        skip_classes = {s["vuln"] for s in skipped}
        self.assertEqual(skip_classes, {"code_injection", "file_inclusion"})

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
        cls.srv.server_close()

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
        eps, _ = self._derive("python_django")
        self.assertEqual({(e.path, e.param, e.vuln) for e in eps},
                         {("/profile/1/", "name", "sqli"), ("/profile/1/", "name", "xss"),
                          ("/go/", "next", "open_redirect")})

    def test_fastapi_sample(self):
        eps, _ = self._derive("python_fastapi")
        self.assertEqual({(e.path, e.param, e.vuln) for e in eps},
                         {("/user", "name", "sqli"), ("/user", "name", "xss"),
                          ("/run", "cmd", "command_injection")})

    def test_path_param_becomes_path_endpoint(self):
        with _project({"main.py": """
            import sqlite3
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/u/{uid}")
            def h(uid: str):
                sqlite3.connect("x").cursor().execute("SELECT * FROM t WHERE id=" + uid)
        """}) as root:
            eps, _ = derive_endpoints(scan_path(root)["findings"],
                                      routes=extract_routes(root))
            self.assertEqual(len(eps), 1)
            e = eps[0]
            self.assertEqual((e.vuln, e.where, e.path_template), ("sqli", "path", "/u/__SBVF__"))

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
        cls.srv.server_close()

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


class TestRepoURLs(unittest.TestCase):
    """Remote scans accept only GitHub, GitLab and Bitbucket https URLs."""

    def test_accepted_and_normalised(self):
        from sbvf.sast.repo import normalize_repo_url as n
        self.assertEqual(n("https://github.com/o/r/tree/main/src"), "https://github.com/o/r.git")
        self.assertEqual(n("github.com/o/r.git"), "https://github.com/o/r.git")
        self.assertEqual(n("https://gitlab.com/g/sub/p/-/blob/main/x.py"),
                         "https://gitlab.com/g/sub/p.git")
        self.assertEqual(n("https://bitbucket.org/ws/r/src/main/"), "https://bitbucket.org/ws/r.git")

    def test_rejected(self):
        from sbvf.sast.repo import RepoURLError, normalize_repo_url
        for bad in ("https://evil.com/o/r", "https://github.com.evil.com/o/r",
                    "http://github.com/o/r", "https://u:p@github.com/o/r",
                    "git@github.com:o/r.git", "https://github.com:444/o/r",
                    "file:///etc/passwd", "https://github.com/o", "https://github.com/-o/r"):
            with self.assertRaises(RepoURLError, msg=bad):
                normalize_repo_url(bad)

    def test_local_vs_remote(self):
        from sbvf.sast.repo import is_repo_url
        self.assertTrue(is_repo_url("https://github.com/o/r"))
        self.assertTrue(is_repo_url("gitlab.com/g/p"))
        self.assertFalse(is_repo_url(r"C:\projects\app"))
        self.assertFalse(is_repo_url("testbed/sast_samples/php_native"))

    def test_self_hosted_gitlab_via_env(self):
        import os
        from unittest import mock
        from sbvf.sast.repo import RepoURLError, normalize_repo_url, is_repo_url
        host = "gitlab.corp.example.com"
        # Rejected by default (no env var set).
        with self.assertRaises(RepoURLError):
            normalize_repo_url(f"https://{host}/group/repo")
        # Accepted, GitLab-style (nested groups + "/-/" separator) once added.
        with mock.patch.dict(os.environ, {"SBVF_EXTRA_GIT_HOSTS": f"other.test, {host}"}):
            self.assertEqual(
                normalize_repo_url(f"https://{host}/group/sub/repo/-/tree/main"),
                f"https://{host}/group/sub/repo.git")
            self.assertEqual(normalize_repo_url(f"{host}/g/p.git"),
                             f"https://{host}/g/p.git")
            self.assertTrue(is_repo_url(f"https://{host}/g/p"))
            # http:// and credentials are still refused on the extra host.
            with self.assertRaises(RepoURLError):
                normalize_repo_url(f"http://{host}/g/p")
            with self.assertRaises(RepoURLError):
                normalize_repo_url(f"https://u:p@{host}/g/p")

    def test_excludes_agent_worktrees(self):
        import os, tempfile
        from sbvf.sast.detect import iter_source_files
        root = tempfile.mkdtemp(prefix="sbvf_prune_")
        try:
            def w(rel, text="x = 1\n"):
                full = os.path.join(root, *rel.split("/"))
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "w", encoding="utf-8") as fh:
                    fh.write(text)
            w("app.py")                       # real source -> kept
            w(".claude/agents/helper.py")     # agent config dir -> skipped by name
            # An agent git worktree under an arbitrarily-named folder: a linked
            # worktree carries a .git *file* at its root -> skipped as nested repo.
            w("agent-run-7/.git", "gitdir: /somewhere/.git/worktrees/agent-run-7\n")
            w("agent-run-7/leaked.py")
            found = {os.path.relpath(f, root).replace("\\", "/")
                     for f in iter_source_files(root)}
            self.assertEqual(found, {"app.py"})
        finally:
            from sbvf.sast.repo import remove_tree
            remove_tree(root)

    def test_list_and_checkout_branches(self):
        import os, shutil, subprocess, tempfile
        from sbvf.sast.repo import (list_branches, checkout_branch, remove_tree,
                                    RepoURLError)
        if not shutil.which("git"):
            self.skipTest("git not installed")
        base = tempfile.mkdtemp(prefix="sbvf_branch_")
        src, clone = os.path.join(base, "src"), os.path.join(base, "clone")

        def git(cwd, *args):
            subprocess.run(["git", "-C", cwd, *args], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        try:
            os.makedirs(src)
            subprocess.run(["git", "init", "-q", src], check=True)
            git(src, "config", "user.email", "t@t.t")
            git(src, "config", "user.name", "t")
            git(src, "symbolic-ref", "HEAD", "refs/heads/main")
            with open(os.path.join(src, "a.py"), "w") as fh:
                fh.write("x = 1\n")
            git(src, "add", "-A"); git(src, "commit", "-q", "-m", "init")
            git(src, "checkout", "-q", "-b", "feature")
            with open(os.path.join(src, "feature_only.py"), "w") as fh:
                fh.write("y = 2\n")
            git(src, "add", "-A"); git(src, "commit", "-q", "-m", "feat")
            git(src, "checkout", "-q", "main")
            subprocess.run(["git", "clone", "-q", "--no-single-branch", src, clone],
                           check=True)

            branches, current = list_branches(clone)
            self.assertEqual(current, "main")
            self.assertEqual(set(branches), {"main", "feature"})   # no bogus "origin"

            checkout_branch(clone, "feature")
            self.assertTrue(os.path.isfile(os.path.join(clone, "feature_only.py")))

            for bad in ("--evil", "", "a..b", "-x"):
                with self.assertRaises(RepoURLError):
                    checkout_branch(clone, bad)
        finally:
            remove_tree(base)

    def test_local_git_branches_and_nondestructive_export(self):
        import os, shutil, subprocess, tempfile
        from sbvf.sast.repo import (is_git_repo, list_branches, export_branch,
                                    remove_tree, RepoURLError)
        if not shutil.which("git"):
            self.skipTest("git not installed")
        base = tempfile.mkdtemp(prefix="sbvf_localbr_")
        src = os.path.join(base, "src")

        def git(*args):
            subprocess.run(["git", "-C", src, *args], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            os.makedirs(src)
            subprocess.run(["git", "init", "-q", src], check=True)
            git("config", "user.email", "t@t.t"); git("config", "user.name", "t")
            git("symbolic-ref", "HEAD", "refs/heads/main")
            with open(os.path.join(src, "a.py"), "w") as fh:
                fh.write("x = 1\n")
            git("add", "-A"); git("commit", "-q", "-m", "init")
            git("checkout", "-q", "-b", "feature")
            with open(os.path.join(src, "feature_only.py"), "w") as fh:
                fh.write("y = 2\n")
            git("add", "-A"); git("commit", "-q", "-m", "feat")
            git("checkout", "-q", "main")

            self.assertTrue(is_git_repo(src))
            self.assertFalse(is_git_repo(base))                 # plain dir, not a repo
            branches, current = list_branches(src)              # local heads, no clone
            self.assertEqual(current, "main")
            self.assertEqual(set(branches), {"main", "feature"})

            exp = export_branch(src, "feature")
            try:
                self.assertTrue(os.path.isfile(os.path.join(exp, "feature_only.py")))
                # the user's own working tree is untouched: still on main, no leak
                self.assertFalse(os.path.isfile(os.path.join(src, "feature_only.py")))
                head = open(os.path.join(src, ".git", "HEAD")).read().strip()
                self.assertTrue(head.endswith("main"))
            finally:
                remove_tree(exp)
            with self.assertRaises(RepoURLError):
                export_branch(src, "--evil")
        finally:
            remove_tree(base)

    def test_credentials_gating(self):
        import os
        from unittest import mock
        from sbvf.sast.repo import _wants_credentials
        selfhosted = "internal.test"          # a reserved, non-routable placeholder host
        with mock.patch.dict(os.environ, {"SBVF_EXTRA_GIT_HOSTS": selfhosted},
                             clear=False):
            os.environ.pop("SBVF_GIT_USE_CREDENTIALS", None)
            self.assertTrue(_wants_credentials(selfhosted))                # self-hosted
            self.assertFalse(_wants_credentials("github.com"))             # public, no flag
            os.environ["SBVF_GIT_USE_CREDENTIALS"] = "1"
            self.assertTrue(_wants_credentials("github.com"))              # flag enables all

    @unittest.skipUnless(os.environ.get("SBVF_NET_TESTS"), "set SBVF_NET_TESTS=1 for network tests")
    def test_real_github_clone(self):
        from sbvf.sast.repo import clone_repo, remove_tree
        d = clone_repo("https://github.com/stamparm/DSVW")
        try:
            self.assertGreaterEqual(len(scan_path(d)["findings"]), 5)
        finally:
            remove_tree(d)
        self.assertFalse(os.path.exists(d))


class TestHttpServerApps(unittest.TestCase):
    """Stdlib http.server apps (e.g. DSVW): self.path is a source, taint flows
    through helper calls, wfile.write / Location headers are sinks."""

    SRC = textwrap.dedent('''
        import http.server, urllib.parse
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                path, query = self.path.split("?", 1)
                params = dict(urllib.parse.parse_qsl(query))
                status, cursor = 200, db.cursor()
                cursor.execute("SELECT * FROM t WHERE id=" + params["id"])
                self.send_header("Location", params["next"])
                self.wfile.write(("<p>%s</p>" % params["q"]).encode())
                self.wfile.write(str(len(params)).encode())
        class NotAHandler:
            def run(self):
                open(self.path)
    ''')

    def test_sources_sinks_and_helpers(self):
        got = {(f.vuln, f.line) for f in PythonAnalyzer("python-native").analyze("a.py", self.SRC)}
        self.assertEqual(got, {("sqli", 8), ("open_redirect", 9), ("xss", 10)})

    def test_tuple_assignment_is_element_wise(self):
        src = ("def v(request):\n"
               "    safe, name = 'x', request.GET['n']\n"
               "    HttpResponse(safe)\n"
               "    HttpResponse(name)\n")
        got = [f.line for f in PythonAnalyzer("django").analyze("v.py", src)]
        self.assertEqual(got, [4])


# --- Node.js: Express and NestJS ----------------------------------------------------

from sbvf.sast.js import JsAnalyzer, lex                       # noqa: E402


class TestExpress(unittest.TestCase):
    def setUp(self):
        self.r = scan_path(os.path.join(SAMPLES, "node_express"))

    def test_framework_detected(self):
        self.assertEqual(self.r["frameworks"]["node"], "express")

    def test_all_planted_found_no_false_positives(self):
        self.assertEqual(_vulns(self.r), {
            ("xss", 13), ("command_injection", 17), ("path_traversal", 21),
            ("open_redirect", 27), ("code_injection", 31),   # app.js
            ("xss", 36), ("xss", 40),                        # Handlebars + Pug render
            ("sqli", 9), ("sqli", 14),                       # routes/users.js
        })

    def test_template_engines(self):
        by_line = {f["line"]: f["sink"] for f in self.r["findings"] if f["vuln"] == "xss"}
        self.assertIn("profile.hbs", by_line[36])        # {{{ }}} Handlebars
        self.assertIn("Handlebars", by_line[36])
        self.assertIn("card.pug", by_line[40])           # != Pug
        self.assertIn("Pug", by_line[40])

    def test_param_and_method(self):
        got = {(f["vuln"], f["line"]): (f["param"], f["method"]) for f in self.r["findings"]}
        self.assertEqual(got[("sqli", 9)], ("name", "GET"))      # const { name } = req.query
        self.assertEqual(got[("sqli", 14)], ("id", "PATH"))      # req.params.id
        self.assertEqual(got[("code_injection", 31)], ("expr", "POST"))


class TestNestJS(unittest.TestCase):
    def setUp(self):
        self.r = scan_path(os.path.join(SAMPLES, "node_nestjs"))

    def test_framework_detected(self):
        self.assertEqual(self.r["frameworks"]["node"], "nestjs")

    def test_all_planted_found_no_false_positives(self):
        got = {(f["vuln"], f["line"], f["function"]) for f in self.r["findings"]}
        self.assertEqual(got, {("sqli", 14, "search"), ("xss", 19, "greet"),
                               ("sqli", 24, "findOne"), ("command_injection", 29, "run")})


class TestJsLexer(unittest.TestCase):
    def test_regex_template_and_asi(self):
        src = textwrap.dedent("""
            const re = /[}{'"]/g
            const msg = `a ${ {x: '}'}.x } b`
            const total = a
              .filter(Boolean)
              .length
            app.get('/x', (req, res) => {
              res.send(req.query.q)
            })
        """)
        stmts, blocks = lex(src)
        texts = [s.text for s in stmts if not s.is_header]
        self.assertTrue(any(t.startswith("const total") and ".length" in t for t in texts))
        route = [b for b in blocks if b.route]
        self.assertEqual(route[0].route, ("app", "GET", "/x"))
        inner = [s for s in stmts if s.text.startswith("res.send")][0]
        self.assertIs(inner.block, route[0])

    def test_decorators_attach_to_method(self):
        src = "@Controller('a')\nexport class A {\n  @Get(':id')\n  one(@Param('id') id: string) {\n    return id\n  }\n}\n"
        _, blocks = lex(src)
        cls = [b for b in blocks if b.kind == "class"][0]
        meth = [b for b in blocks if b.name == "one"][0]
        self.assertEqual(cls.decorators, ["@Controller('a')"])
        self.assertEqual(meth.decorators, ["@Get(':id')"])
        self.assertIs(meth.parent, cls)

    def test_scopes_do_not_leak_between_handlers(self):
        src = ("app.get('/a', (req, res) => { const q = req.query.q; res.send('ok') })\n"
               "app.get('/b', (req, res) => { const q = 'static'; res.send('<p>' + q) })\n")
        self.assertEqual(JsAnalyzer("express").analyze("a.js", src), [])

    def test_identifier_inside_string_is_not_a_use(self):
        src = ("module.exports.bulk = function (req, res) {\n"
               "  var products = serialize.unserialize(req.files.p.data)\n"
               "  res.redirect('/app/products')\n"
               "}\n")
        got = [(f.vuln, f.line) for f in JsAnalyzer("express").analyze("a.js", src)]
        self.assertEqual(got, [("code_injection", 2)])      # not the constant redirect

    def test_commonjs_handlers_get_their_own_scope(self):
        src = ("module.exports.a = function (req, res) { var query = req.body.q }\n"
               "module.exports.b = function (req, res) { res.send('<p>' + query) }\n")
        self.assertEqual(JsAnalyzer("express").analyze("a.js", src), [])

    def test_mathjs_and_node_serialize_rce(self):
        src = ("app.post('/c', (req, res) => { res.json(mathjs.eval(req.body.eqn)) })\n"
               "app.post('/u', (req, res) => { serialize.unserialize(req.body.blob) })\n")
        got = {f.vuln for f in JsAnalyzer("express").analyze("a.js", src)}
        self.assertEqual(got, {"code_injection"})

    def test_ejs_raw_output_vs_escaped(self):
        with _project({
            "package.json": '{"dependencies": {"express": "4"}}',
            "app.js": ("const app = require('express')()\n"
                       "app.get('/p', (req, res) => {\n"
                       "  res.render('raw', { output: { term: req.query.q } })\n"
                       "})\n"
                       "app.get('/s', (req, res) => {\n"
                       "  res.render('safe', { output: { term: req.query.q } })\n"
                       "})\n"),
            "views/raw.ejs": "<h1>\n  Results: <%- output.term %>\n</h1>\n",
            "views/safe.ejs": "<h1>Results: <%= output.term %></h1>\n",
        }) as root:
            r = scan_path(root)
            got = [(f["vuln"], f["line"], f["param"]) for f in r["findings"]]
            self.assertEqual(got, [("xss", 3, "q")])
            self.assertIn("views/raw.ejs:2", r["findings"][0]["sink"])

    def test_regex_exec_is_not_command_injection(self):
        src = ("const cp = require('child_process')\n"
               "app.get('/a', (req, res) => { const m = /(\\d+)/.exec(req.query.q); res.json(m) })\n")
        self.assertEqual(JsAnalyzer("express").analyze("a.js", src), [])


class TestNodeRoutesAndBridge(unittest.TestCase):
    def _derive(self, sample):
        root = os.path.join(SAMPLES, sample)
        return derive_endpoints(scan_path(root)["findings"], routes=extract_routes(root))

    def test_express_mount_prefix(self):
        routes = extract_routes(os.path.join(SAMPLES, "node_express"))
        self.assertEqual(routes[("routes/users", "@L7")][0].path, "/users")
        self.assertEqual(routes[("routes/users", "@L13")][0].path_params, ("id",))

    def test_nest_global_and_controller_prefix(self):
        routes = extract_routes(os.path.join(SAMPLES, "node_nestjs"))
        r = routes[("src/users/users.controller", "findOne")][0]
        self.assertEqual((r.path, r.template), ("/api/users/1", "/api/users/:id"))

    def test_derived_endpoints(self):
        eps, _ = self._derive("node_express")
        self.assertEqual({(e.path, e.param, e.vuln, e.method, e.where) for e in eps}, {
            ("/search", "q", "xss", "GET", "query"),
            ("/profile", "bio", "xss", "GET", "query"),      # Handlebars render
            ("/card", "name", "xss", "GET", "query"),        # Pug render
            ("/ping", "host", "command_injection", "GET", "query"),
            ("/go", "next", "open_redirect", "GET", "query"),
            ("/users", "name", "sqli", "GET", "query"),
            ("/users/1", "id", "sqli", "GET", "path"),       # URL path segment
        })
        byp = {e.path: e for e in eps}
        self.assertEqual(byp["/users/1"].path_template, "/users/__SBVF__")

        eps, _ = self._derive("node_nestjs")
        self.assertEqual({(e.path, e.param, e.vuln, e.method, e.where) for e in eps}, {
            ("/api/users/search", "name", "sqli", "GET", "query"),
            ("/api/users/greet", "who", "xss", "GET", "query"),
            ("/api/users/1", "id", "sqli", "GET", "path"),
            ("/api/users/run", "cmd", "command_injection", "POST", "body"),
        })

    def test_named_handler_in_other_module(self):
        with _project({
            "package.json": '{"dependencies": {"express": "4"}}',
            "app.js": ("const express = require('express')\n"
                       "const h = require('./handlers')\n"
                       "const app = express()\n"
                       "app.get('/find', h.find)\n"),
            "handlers.js": ("exports.find = (req, res) => {\n"
                            "  res.send('<b>' + req.query.term + '</b>')\n"
                            "}\n"),
        }) as root:
            eps, _ = derive_endpoints(scan_path(root)["findings"], routes=extract_routes(root))
            self.assertEqual([(e.path, e.param, e.vuln) for e in eps], [("/find", "term", "xss")])


class TestGuidedNodeConfirmation(unittest.TestCase):
    """End-to-end on Node stacks: Express and NestJS projects are scanned
    statically, their routes recovered, and the derived endpoints confirmed by
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
        cls.srv.server_close()

    def _confirm(self, files, algo):
        with _project(files) as root:
            eps, _ = derive_endpoints(scan_path(root)["findings"],
                                      routes=extract_routes(root))
        self.assertEqual(len(eps), 1)
        report = run_external(self.base, eps, runs=1, budget=200,
                              methods={algo: ALGORITHMS[algo]})
        return eps[0], report[0]["methods"][algo]["detections"]

    def test_express_xss_route_confirmed(self):
        ep, hits = self._confirm({
            "package.json": '{"dependencies": {"express": "4"}}',
            "server.js": ("const express = require('express')\n"
                          "const app = express()\n"
                          "const xss = express.Router()\n"
                          "app.use('/xss', xss)\n"
                          "xss.get('/reflect_raw', (req, res) => {\n"
                          "  const { q } = req.query\n"
                          "  res.send(`<p>${q}</p>`)\n"
                          "})\n"),
        }, "GA")
        self.assertEqual((ep.path, ep.param, ep.vuln), ("/xss/reflect_raw", "q", "xss"))
        self.assertEqual(hits, 1)

    def test_nest_sqli_route_confirmed(self):
        ep, hits = self._confirm({
            "package.json": '{"dependencies": {"@nestjs/core": "10"}}',
            "src/sqli.controller.ts": (
                "import { Controller, Get, Query } from '@nestjs/common'\n"
                "@Controller('sqli')\n"
                "export class SqliController {\n"
                "  constructor(private readonly db: DataSource) {}\n"
                "  @Get('error')\n"
                "  find(@Query('name') name: string) {\n"
                "    return this.db.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n"
                "  }\n"
                "}\n"),
        }, "CS")
        self.assertEqual((ep.path, ep.param, ep.vuln), ("/sqli/error", "name", "sqli"))
        self.assertEqual(hits, 1)


# --- dynamic confirmation of command injection / redirect / POST / path -------------

def _shell_echoes_marker(value: str) -> bool:
    """Faithfully model `exec('ping ' + value)`: a shell runs the injected
    `echo <marker>` after a metacharacter, so the marker reaches the output. No
    real shell is spawned -- this mirrors the behaviour deterministically."""
    for sep in (";", "|", "&&", "&", "`", "$("):
        if sep in value:
            tail = value.split(sep, 1)[1]
            if CMDI_MARKER in tail:
                return True
    return "`echo %s`" % CMDI_MARKER in value or "$(echo %s)" % CMDI_MARKER in value


class _VulnMock(BaseHTTPRequestHandler):
    """A deterministic 'vulnerable' app exercising each injection site/class."""

    def log_message(self, *a):
        pass

    def _reply(self, status, body, headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        seg = urllib.parse.unquote(parsed.path.strip("/").split("/")[-1])
        q = urllib.parse.parse_qs(parsed.query)
        path = parsed.path
        if path.startswith("/exec"):                       # command injection (query)
            val = q.get("host", [""])[0]
            return self._reply(200, "PING ok\n" + (CMDI_MARKER if _shell_echoes_marker(val) else ""))
        if path.startswith("/redirect"):                   # open redirect (query), no-follow
            return self._reply(302, "", {"Location": q.get("next", [""])[0]})
        if path.startswith("/item/"):                      # SQLi via URL path segment
            body = "sqlite3.OperationalError: near syntax error" if "'" in seg else "row"
            return self._reply(200, body)
        return self._reply(404, "nope")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        if self.path.startswith("/run"):                   # command injection (POST body)
            val = form.get("cmd", [""])[0]
            return self._reply(200, "run\n" + (CMDI_MARKER if _shell_echoes_marker(val) else ""))
        return self._reply(404, "nope")


class TestDynamicConfirmation(unittest.TestCase):
    """The search confirms command injection, open redirect, POST-body and
    URL-path-segment injections against a deterministic vulnerable mock."""

    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _VulnMock)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def _run(self, ep, algo="GA", budget=300):
        rep = run_external(self.base, [ep], runs=1, budget=budget,
                           methods={algo: ALGORITHMS[algo]})
        return rep[0]["methods"][algo]["detections"]

    def test_command_injection_query(self):
        ep = ExternalEndpoint("/exec", "host", "command_injection", method="GET", where="query")
        self.assertEqual(self._run(ep), 1)

    def test_command_injection_post_body(self):
        ep = ExternalEndpoint("/run", "cmd", "command_injection", method="POST", where="body")
        self.assertEqual(self._run(ep), 1)

    def test_open_redirect_query(self):
        ep = ExternalEndpoint("/redirect", "next", "open_redirect", method="GET", where="query")
        self.assertEqual(self._run(ep, algo="CS"), 1)

    def test_sqli_url_path_segment(self):
        ep = ExternalEndpoint("/item/1", "id", "sqli", method="GET", where="path",
                              path_template="/item/__SBVF__")
        self.assertEqual(self._run(ep, algo="RS"), 1)

    def test_no_false_positive_on_safe_redirect(self):
        # an app that ignores `next` and never sets Location is not confirmed
        class _Safe(_VulnMock):
            def do_GET(self):
                self._reply(200, "home")
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Safe)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.1)
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            ep = ExternalEndpoint("/redirect", "next", "open_redirect", where="query")
            rep = run_external(base, [ep], runs=1, budget=120,
                               methods={"GA": ALGORITHMS["GA"]})
            self.assertEqual(rep[0]["methods"]["GA"]["detections"], 0)
        finally:
            srv.shutdown()
            srv.server_close()


# --- live Node.js runner (opt-in: set SBVF_NODE_TESTS=1; needs node on PATH) --------

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _node_available() -> bool:
    try:
        subprocess.run(["node", "--version"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


@unittest.skipUnless(os.environ.get("SBVF_NODE_TESTS") and _node_available(),
                     "set SBVF_NODE_TESTS=1 and install Node.js for live-runner tests")
class TestLiveNodeRunner(unittest.TestCase):
    """Launch a real Node.js process locally and confirm a derived endpoint
    against it with the search -- the full static-guided flow end to end."""

    def _launch(self, files, start):
        tmp = tempfile.TemporaryDirectory()
        for rel, src in files.items():
            path = os.path.join(tmp.name, rel)
            os.makedirs(os.path.dirname(path) or tmp.name, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(textwrap.dedent(src))
        proc, base = self._spawn(tmp.name, start)
        return proc, base, tmp

    def _spawn(self, app_dir, start):
        port = _free_port()
        env = dict(os.environ, PORT=str(port), HOST="127.0.0.1")
        proc = subprocess.Popen(start, cwd=app_dir, env=env, shell=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_port(port):
            proc.kill()
            self.skipTest("the Node app did not come up")
        return proc, f"http://127.0.0.1:{port}"

    def _stop(self, proc, tmp):
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        tmp.cleanup()

    def test_builtin_http_command_injection(self):
        # No npm needed: a real Node http server, intentionally vulnerable, that
        # emulates the shell result deterministically (no child process spawned).
        proc, base, tmp = self._launch({"app.js": """
            const http = require('http');
            const MARK = 'SBVFcmdi7r3';
            http.createServer((req, res) => {
              const u = new URL(req.url, 'http://x');
              if (u.pathname === '/exec') {
                const host = u.searchParams.get('host') || '';
                const ran = /[;|&`$(]/.test(host) && host.includes('echo ' + MARK);
                res.end('PING ' + (ran ? MARK : 'ok'));
              } else { res.statusCode = 404; res.end('no'); }
            }).listen(process.env.PORT, '127.0.0.1');
        """}, "node app.js")
        try:
            ep = ExternalEndpoint("/exec", "host", "command_injection")
            rep = run_external(base, [ep], runs=1, budget=300,
                               methods={"GA": ALGORITHMS["GA"]})
            self.assertEqual(rep[0]["methods"]["GA"]["detections"], 1)
        finally:
            self._stop(proc, tmp)

    def test_express_from_sast_end_to_end(self):
        # Full flow: npm install express -> launch -> static scan -> derive -> search.
        files = {
            "package.json": '{"name":"t","private":true,'
                            '"dependencies":{"express":"^4.19.2"}}',
            "server.js": """
                const express = require('express');
                const app = express();
                app.get('/search', (req, res) => {
                  res.send('<h1>' + req.query.q + '</h1>');   // reflected XSS
                });
                app.listen(process.env.PORT || 3000, '127.0.0.1');
            """,
        }
        tmp = tempfile.TemporaryDirectory()
        for rel, src in files.items():
            with open(os.path.join(tmp.name, rel), "w", encoding="utf-8") as fh:
                fh.write(textwrap.dedent(src))
        from sbvf.sast import noderun
        ok, msg = noderun.install_deps(tmp.name, timeout=240)
        if not ok:
            tmp.cleanup()
            self.skipTest(f"npm install unavailable: {msg}")
        eps, _ = derive_endpoints(scan_path(tmp.name)["findings"],
                                  routes=extract_routes(tmp.name))
        self.assertTrue(any(e.path == "/search" and e.vuln == "xss" for e in eps))
        # launch in the SAME dir that now has node_modules from the install above
        proc, base = self._spawn(tmp.name, noderun.detect_start(tmp.name))
        try:
            rep = run_external(base, [e for e in eps if e.path == "/search"],
                               runs=1, budget=200, methods={"GA": ALGORITHMS["GA"]})
            self.assertEqual(rep[0]["methods"]["GA"]["detections"], 1)
        finally:
            self._stop(proc, tmp)


class TestIDOR(unittest.TestCase):
    """IDOR (OWASP A01): a request-controlled id reaching a by-id data fetch with
    no ownership/authorization check. Guarded handlers must not be flagged."""

    def _v(self, fw, src, name="a"):
        ext = ".py" if fw in ("django", "fastapi", "python-native") else \
              (".php" if "php" in fw else ".ts" if fw == "nestjs" else ".js")
        mod = {"django": PythonAnalyzer, "fastapi": PythonAnalyzer,
               "nestjs": JsAnalyzer, "express": JsAnalyzer, "laravel": PhpAnalyzer}[fw]
        return [f.vuln for f in mod(fw).analyze(name + ext, textwrap.dedent(src))]

    def test_django_objects_get(self):
        self.assertIn("idor", self._v("django",
            "def view(request, oid):\n    o = Order.objects.get(pk=oid)\n    return o\n"))

    def test_django_scoped_is_safe(self):
        self.assertNotIn("idor", self._v("django",
            "def view(request, oid):\n    o = Order.objects.get(pk=oid, user=request.user)\n    return o\n"))

    def test_django_decorator_guard_is_safe(self):
        self.assertNotIn("idor", self._v("django",
            "@permission_required('x')\ndef view(request, oid):\n    return Order.objects.get(pk=oid)\n"))

    def test_fastapi_sqlalchemy_get(self):
        self.assertIn("idor", self._v("fastapi",
            "@app.get('/o/{oid}')\ndef view(oid: int):\n    return session.query(Order).get(oid)\n"))

    def test_express_findbyid(self):
        self.assertIn("idor", self._v("express",
            "app.get('/o/:id',(req,res)=>{ res.json(Order.findById(req.params.id)); })\n"))

    def test_express_user_scoped_is_safe(self):
        self.assertNotIn("idor", self._v("express",
            "app.get('/o/:id',(req,res)=>{ res.json(Order.findOne({_id:req.params.id,userId:req.user.id})); })\n"))

    def test_nest_useguards_is_safe(self):
        self.assertNotIn("idor", self._v("nestjs",
            "@Controller('o')\nexport class C {\n  @UseGuards(AuthGuard)\n  @Get(':id')\n"
            "  one(@Param('id') id: string){ return this.repo.findOne(id); }\n}\n"))

    def test_nest_unguarded_is_flagged(self):
        self.assertIn("idor", self._v("nestjs",
            "@Controller('o')\nexport class C {\n  @Get(':id')\n"
            "  one(@Param('id') id: string){ return this.repo.findOne(id); }\n}\n"))

    def test_laravel_find(self):
        self.assertIn("idor", self._v("laravel",
            "<?php class C { function show(){ $id=request()->input('id'); return Order::findOrFail($id); } }"))

    def test_laravel_auth_is_safe(self):
        self.assertNotIn("idor", self._v("laravel",
            "<?php class C { function show(){ $id=request()->input('id'); "
            "return Order::where('user_id', auth()->id())->findOrFail($id); } }"))

    def test_bundled_django_sample(self):
        r = scan_path(os.path.join(SAMPLES, "idor_django"))
        self.assertEqual(r["frameworks"]["python"], "django")
        self.assertEqual([(f["vuln"], f["line"]) for f in r["findings"]], [("idor", 13)])

    def test_idor_metadata_in_report(self):
        fs = PythonAnalyzer("django").analyze(
            "v.py", "def view(request, oid):\n    return Order.objects.get(pk=oid)\n")
        d = fs[0].to_dict()
        self.assertEqual(d["cwe"], "CWE-639")
        self.assertTrue(d["impact"] and d["fix"] and d["how_in"])

    def test_idor_bridges_to_dynamic_endpoints(self):
        # A routed IDOR finding is handed to the search two ways: as IDOR (enumerate
        # object ids as a low-privilege user) and as a missing-authentication probe
        # (is the same record served with no identity -> a public endpoint).
        with _project({
            "manage.py": "", "urls.py": "from django.urls import path\nfrom . import views\n"
            "urlpatterns=[path('orders/<int:oid>/', views.get_order)]\n",
            "views.py": "def get_order(request, oid):\n    return Order.objects.get(pk=oid)\n",
        }) as root:
            eps, skipped = derive_endpoints(scan_path(root)["findings"], routes=extract_routes(root))
            self.assertEqual(sorted({e.vuln for e in eps}), ["idor", "missing_auth"])
            for e in eps:
                self.assertEqual((e.where, e.param), ("path", "oid"))
                self.assertEqual(e.path_template, "/orders/__SBVF__/")


class TestIDORPrecision(unittest.TestCase):
    """Regression tests for the IDOR guard precision fixes (code-review findings):
    the guard must reflect a real authorization action or a query scoped to the
    user, not the mere presence of a common variable name."""

    def _py(self, s):
        return [f.vuln for f in PythonAnalyzer("django").analyze("v.py", textwrap.dedent(s))]

    def _js(self, s):
        return [f.vuln for f in JsAnalyzer("express").analyze("a.js", textwrap.dedent(s))]

    def _php(self, s):
        return [(f.vuln, f.line) for f in PhpAnalyzer("laravel").analyze("C.php", textwrap.dedent(s))]

    def test_py_common_var_name_no_longer_suppresses(self):
        self.assertIn("idor", self._py(
            "def view(request, oid):\n    account = oid\n    return Thing.objects.get(pk=oid)\n"))

    def test_py_comparison_no_longer_suppresses(self):
        self.assertIn("idor", self._py(
            "def view(request, oid):\n    if user == oid:\n        pass\n    return T.objects.get(pk=oid)\n"))

    def test_py_scoped_fetch_still_safe(self):
        self.assertNotIn("idor", self._py(
            "def view(request, oid):\n    return Order.objects.get(pk=oid, user=request.user)\n"))

    def test_js_id_variable_named_userid_is_flagged(self):
        self.assertIn("idor", self._js(
            "app.get('/u/:id',(req,res)=>{ const userId=req.params.id; res.json(User.findById(userId)); })\n"))

    def test_js_outer_guard_covers_nested_callback(self):
        self.assertNotIn("idor", self._js(
            "app.get('/o/:id',(req,res)=>{ if(!req.user) return res.sendStatus(401);\n"
            "  db.q((e)=>{ Order.findById(req.params.id); }); })\n"))

    def test_js_scoped_query_is_safe(self):
        self.assertNotIn("idor", self._js(
            "app.get('/o/:id',(req,res)=>{ res.json(Order.findOne({_id:req.params.id, userId:req.user.id})); })\n"))

    def test_php_guard_is_per_method(self):
        got = self._php(
            "<?php\nclass Ctrl {\n"
            "  public function show() { $id=request()->input('id'); return Order::findOrFail($id); }\n"
            "  public function mine() { $id=request()->input('id'); return Order::where('user_id', auth()->id())->findOrFail($id); }\n}\n")
        self.assertEqual([v for v, _ in got], ["idor"])   # only show(), not mine()

    def test_php_collection_find_not_flagged(self):
        self.assertEqual(self._php(
            "<?php class C { function g(){ $id=$_GET['id']; return collect($rows)->find($id); } }"), [])


class TestCryptoFailures(unittest.TestCase):
    """OWASP A04: pattern rules fire on the vulnerable sample, not on safe code."""

    def setUp(self):
        self.r = scan_path(os.path.join(SAMPLES, "crypto_py"))
        self.src = open(os.path.join(SAMPLES, "crypto_py", "app.py")).read().splitlines()

    def _line(self, needle):
        return next(i for i, l in enumerate(self.src, 1) if needle in l)

    def test_each_rule_fires_on_vulnerable_code(self):
        got = _vulns(self.r)
        self.assertIn(("weak_crypto", self._line("hashlib.md5")), got)
        self.assertIn(("broken_tls", self._line("verify=False")), got)
        self.assertIn(("hardcoded_secret", self._line("SECRET_KEY =")), got)
        self.assertIn(("weak_random", self._line("random.randint")), got)

    def test_safe_counterparts_not_flagged(self):
        self.assertSetEqual(
            {v for v, _ in _vulns(self.r)},
            {"weak_crypto", "broken_tls", "hardcoded_secret", "weak_random"})
        self.assertEqual(len(self.r["findings"]), 4)        # nothing from the safe block

    def test_metadata(self):
        f = {x["vuln"]: x for x in self.r["findings"]}
        self.assertEqual((f["weak_crypto"]["cwe"], f["weak_crypto"]["severity"]), ("CWE-327", "medium"))
        self.assertEqual((f["broken_tls"]["cwe"], f["broken_tls"]["severity"]), ("CWE-295", "high"))
        self.assertEqual((f["hardcoded_secret"]["cwe"], f["hardcoded_secret"]["severity"]), ("CWE-798", "high"))
        self.assertEqual((f["weak_random"]["cwe"], f["weak_random"]["severity"]), ("CWE-338", "medium"))
        for x in f.values():
            self.assertTrue(x["fix"] and x["impact"] and x["owner"] and x["exposure"] and x["how_in"])

    def test_streams_finding_steps(self):
        steps = []
        scan_path(os.path.join(SAMPLES, "crypto_py"), on_step=steps.append)
        self.assertEqual(sum(1 for s in steps if s.kind == "finding"), 4)

    def _scan(self, name, code):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, name), "w") as fh:
                fh.write(code)
            return {f["vuln"] for f in scan_path(d)["findings"]}

    def test_python_variants(self):
        self.assertIn("weak_crypto", self._scan("a.py", "import hashlib\nh = hashlib.sha1(b'x')\n"))
        self.assertIn("weak_crypto", self._scan("a.py", "c = AES.new(k, AES.MODE_ECB)\n"))
        self.assertIn("broken_tls", self._scan("a.py", "import ssl\nc = ssl._create_unverified_context()\n"))
        self.assertIn("weak_random", self._scan("a.py", "import random\ntoken = random.choice('abc')\n"))
        for safe in ("import hashlib\nh = hashlib.sha256(b'x')\n",
                     "import os\nPASSWORD = os.environ.get('PW')\n",
                     "import secrets\ntoken = secrets.token_hex(8)\n",
                     "import requests\nrequests.get(u, verify=True)\n",
                     "h = hashlib.md5(b'x', usedforsecurity=False)\n"):
            self.assertEqual(self._scan("a.py", safe), set(), safe)

    def test_js_variants(self):
        self.assertIn("weak_crypto", self._scan("a.js", "const h = crypto.createHash('md5').update(p).digest('hex');\n"))
        self.assertIn("weak_crypto", self._scan("a.js", "const c = crypto.createCipheriv('aes-128-ecb', k, null);\n"))
        self.assertIn("broken_tls", self._scan("a.js", "const a = new https.Agent({ rejectUnauthorized: false });\n"))
        self.assertIn("broken_tls", self._scan("a.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n"))
        self.assertIn("hardcoded_secret", self._scan("a.js", "const jwtSecret = 'my-super-secret';\n"))
        self.assertIn("weak_random", self._scan("a.js", "const token = Math.random().toString(36);\n"))
        for safe in ("const h = crypto.createHash('sha256');\n",
                     "const jwtSecret = process.env.JWT_SECRET;\n",
                     "const token = crypto.randomBytes(16).toString('hex');\n",
                     "const x = Math.random() * 10;\n",
                     "const a = new https.Agent({ rejectUnauthorized: true });\n"):
            self.assertEqual(self._scan("a.js", safe), set(), safe)

    def test_php_variants(self):
        self.assertIn("weak_crypto", self._scan("a.php", "<?php $h = md5($pw);\n"))
        self.assertIn("weak_crypto", self._scan("a.php", "<?php $h = sha1($pw);\n"))
        self.assertIn("broken_tls", self._scan("a.php", "<?php curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);\n"))
        self.assertIn("broken_tls", self._scan("a.php", "<?php curl_setopt($c, CURLOPT_SSL_VERIFYHOST, 0);\n"))
        self.assertIn("hardcoded_secret", self._scan("a.php", "<?php $apiKey = 'abcdef123456';\n"))
        self.assertIn("weak_random", self._scan("a.php", "<?php $token = mt_rand();\n"))
        self.assertIn("weak_random", self._scan("a.php", "<?php $token = uniqid();\n"))
        for safe in ("<?php $h = password_hash($pw, PASSWORD_BCRYPT);\n",
                     "<?php curl_setopt($c, CURLOPT_SSL_VERIFYPEER, true);\n",
                     "<?php $apiKey = getenv('API_KEY');\n",
                     "<?php $token = bin2hex(random_bytes(16));\n"):
            self.assertEqual(self._scan("a.php", safe), set(), safe)

    def test_existing_samples_have_no_crypto_findings(self):
        crypto_vulns = {"weak_crypto", "broken_tls", "hardcoded_secret", "weak_random"}
        for name in os.listdir(SAMPLES):
            if name == "crypto_py":
                continue
            r = scan_path(os.path.join(SAMPLES, name))
            self.assertFalse(
                [f for f in r["findings"] if f["vuln"] in crypto_vulns], name)


class TestCryptoRulePrecision(unittest.TestCase):
    """Regression tests for the A04 code-review findings: hardcoded-secret must
    key off real identifier components, not substrings of ordinary names."""

    def _v(self, line):
        from sbvf.sast.rules import scan_text
        return [f.vuln for f in scan_text("a.py", line)]

    def test_common_identifiers_not_flagged(self):
        for line in ("driver = 'postgresql'", "cache_key = 'user:12345'",
                     "author = 'janedoe2024'", "sort_key = 'created_at'",
                     "archive = 'backups/2024'", "foreign_key = 'orders.id'",
                     "message = 'hello there friend'"):
            self.assertNotIn("hardcoded_secret", self._v(line), line)

    def test_real_secret_names_flagged(self):
        for line in ("api_key = 'AKIA1234567890'", "SECRET_KEY = 'django-insecure-xyz'",
                     "password = 'hunter2secret'", "jwt_secret = 'abc123def456'",
                     "sessionKey = 'abc123def456'"):
            self.assertIn("hardcoded_secret", self._v(line), line)

    def test_weak_random_bare_key_not_context(self):
        # a standalone 'key' is no longer enough context for weak-random
        self.assertNotIn("weak_random", self._v("chosen = random.choice(the_key_list)"))

    def test_laravel_cast_directives_not_secret(self):
        # a secret-named attribute mapped to a framework cast directive (Laravel
        # $casts / casts()) is a cast instruction, not a hardcoded secret.
        for line in ("        'password' => 'hashed',",
                     "        'secret_token' => 'encrypted',",
                     "        'ssn' => 'encrypted:array',",
                     "        'api_key' => 'encrypted:json',"):
            self.assertNotIn("hardcoded_secret", self._v(line), line)

    def test_real_secret_in_array_still_flagged(self):
        # the fix must not suppress a genuine hardcoded secret in array syntax
        for line in ("        'password' => 'hunter2secret',",
                     "        'api_key' => 'AKIA1234567890',"):
            self.assertIn("hardcoded_secret", self._v(line), line)

    def _vf(self, rel, line):
        from sbvf.sast.rules import scan_text
        return [f.vuln for f in scan_text(rel, line)]

    def test_placeholder_values_not_flagged(self):
        # reported FP: a key assigned an obvious placeholder is not a secret.
        for line in ("        'apiKey' => 'your_api_key',",
                     "        'token' => 'changeme',",
                     "        'secret' => '<your-secret-here>',",
                     "        'password' => 'placeholder',"):
            self.assertNotIn("hardcoded_secret", self._v(line), line)

    def test_i18n_message_values_not_flagged(self):
        # reported FP: Arabic/English UI strings in a message catalogue are prose,
        # not secrets -- both by value (whitespace) and by path (messages/ dir).
        rel = "protected/messages/ar/app_messages.php"
        for line in ("    'password' => 'إسم المستخدم أو كلمة السر غير صحيحة',",
                     "    'incorrect_password' => 'كلمة السر غير صحيحة',",
                     "    'password_should_be_strong' => 'يجب أن تحتوي كلمة السر على الأقل',"):
            self.assertNotIn("hardcoded_secret", self._vf(rel, line), line)
        # the whitespace veto also catches a prose value outside a messages dir
        self.assertNotIn("hardcoded_secret",
                         self._v("    'incorrect_password' => 'كلمة السر غير صحيحة',"))

    def test_enum_label_echoing_key_not_flagged(self):
        # reported FP: a const whose value just echoes the key is an enum label.
        for line in ("    const SCENARIO_PASSWORD_CHANGE = 'passwordChange';",
                     "        'password' => 'password',"):
            self.assertNotIn("hardcoded_secret", self._v(line), line)

    def test_test_fixture_tokens_not_flagged(self):
        # reported FP: fake tokens in a test fixture file are not real secrets.
        line = "    'c_device_token' => 'DEADBEEF-0000-4000-8000-FEEDFACE0000',"
        for rel in ("protected/tests/fixtures/api_token.php",
                    "app/__tests__/auth.spec.js", "src/user.test.js"):
            self.assertNotIn("hardcoded_secret", self._vf(rel, line), rel)
        # but the same token in real application code is still flagged
        self.assertIn("hardcoded_secret",
                      self._vf("protected/components/Api.php", line))


class TestSecurityMisconfig(unittest.TestCase):
    """OWASP A02: config pattern rules fire on the misconfigured sample, not on
    the hardened counterpart."""

    def setUp(self):
        self.r = scan_path(os.path.join(SAMPLES, "misconfig_py"))
        self.src = open(os.path.join(SAMPLES, "misconfig_py", "app.py")).read().splitlines()

    def _line(self, needle):
        return next(i for i, l in enumerate(self.src, 1) if needle in l)

    def test_each_rule_fires_on_vulnerable_code(self):
        got = _vulns(self.r)
        self.assertIn(("debug_enabled", self._line("DEBUG = True")), got)
        self.assertIn(("security_misconfig", self._line('ALLOWED_HOSTS = ["*"]')), got)
        self.assertIn(("insecure_cookie", self._line("SESSION_COOKIE_SECURE = False")), got)
        self.assertIn(("permissive_cors", self._line("CORS(app)")), got)

    def test_each_rule_present_exactly(self):
        self.assertSetEqual(
            {v for v, _ in _vulns(self.r)},
            {"debug_enabled", "security_misconfig", "insecure_cookie", "permissive_cors"})

    def test_safe_counterpart_not_flagged(self):
        # Scan the hardened file in isolation: a false positive here would be
        # invisible if we only checked the vuln *set* of the whole directory.
        from sbvf.sast.rules import scan_text
        safe = open(os.path.join(SAMPLES, "misconfig_py", "safe.py")).read()
        self.assertEqual([f.vuln for f in scan_text("safe.py", safe)], [])

    def test_metadata(self):
        f = {x["vuln"]: x for x in self.r["findings"]}
        self.assertEqual((f["debug_enabled"]["cwe"], f["debug_enabled"]["severity"]), ("CWE-489", "high"))
        self.assertEqual((f["permissive_cors"]["cwe"], f["permissive_cors"]["severity"]), ("CWE-942", "medium"))
        self.assertEqual((f["insecure_cookie"]["cwe"], f["insecure_cookie"]["severity"]), ("CWE-614", "medium"))
        self.assertEqual((f["security_misconfig"]["cwe"], f["security_misconfig"]["severity"]), ("CWE-16", "medium"))
        for x in f.values():
            self.assertTrue(x["fix"] and x["impact"] and x["owner"] and x["exposure"] and x["how_in"])

    def test_streams_finding_steps(self):
        steps = []
        scan_path(os.path.join(SAMPLES, "misconfig_py"), on_step=steps.append)
        self.assertTrue(sum(1 for s in steps if s.kind == "finding") >= 4)

    def _scan(self, name, code):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, name), "w") as fh:
                fh.write(code)
            return {f["vuln"] for f in scan_path(d)["findings"]}

    def test_python_variants(self):
        self.assertIn("debug_enabled", self._scan("a.py", "DEBUG = True\n"))
        self.assertIn("debug_enabled", self._scan("a.py", "app.run(debug=True)\n"))
        self.assertIn("security_misconfig", self._scan("a.py", 'ALLOWED_HOSTS = ["*"]\n'))
        self.assertIn("insecure_cookie", self._scan("a.py", "SESSION_COOKIE_SECURE = False\n"))
        self.assertIn("permissive_cors", self._scan("a.py", "CORS(app)\n"))
        for safe in ("DEBUG = False\n",
                     'ALLOWED_HOSTS = ["app.example.com"]\n',
                     "SESSION_COOKIE_SECURE = True\n",
                     'CORS(app, origins=["https://app.example.com"])\n'):
            self.assertEqual(self._scan("a.py", safe), set(), safe)

    def test_rule_precision(self):
        from sbvf.sast.rules import scan_text
        # a bare JS `debug: true` object key is benign config, not a finding
        self.assertNotIn("debug_enabled",
            [f.vuln for f in scan_text("webpack.config.js",
                "module.exports = { devtool: 'source-map', debug: true };")])
        # a non-cookie `secure=False` kwarg must not be misreported as a cookie
        for line in ("conn = driver.connect(host=h, secure=False)",
                     "client = Thing(secure=False)"):
            self.assertNotIn("insecure_cookie",
                [f.vuln for f in scan_text("a.py", line)], line)

    def test_existing_samples_have_no_misconfig_findings(self):
        misconfig_vulns = {"debug_enabled", "security_misconfig",
                           "insecure_cookie", "permissive_cors"}
        for name in os.listdir(SAMPLES):
            if name == "misconfig_py":
                continue
            r = scan_path(os.path.join(SAMPLES, name))
            self.assertFalse(
                [f for f in r["findings"] if f["vuln"] in misconfig_vulns], name)


class TestInsecureDeserialization(unittest.TestCase):
    """OWASP A08: deserialization pattern rules fire on the vulnerable sample,
    not on the hardened counterpart."""

    def setUp(self):
        self.r = scan_path(os.path.join(SAMPLES, "deser_py"))
        self.src = open(os.path.join(SAMPLES, "deser_py", "app.py")).read().splitlines()

    def _line(self, needle):
        return next(i for i, l in enumerate(self.src, 1) if needle in l)

    def test_each_sink_fires_on_vulnerable_code(self):
        got = _vulns(self.r)
        self.assertIn(("insecure_deserialization", self._line("pickle.loads")), got)
        self.assertIn(("insecure_deserialization", self._line("marshal.loads")), got)
        self.assertIn(("insecure_deserialization", self._line("yaml.load(")), got)

    def test_only_deserialization_findings(self):
        self.assertSetEqual({v for v, _ in _vulns(self.r)}, {"insecure_deserialization"})
        self.assertEqual(len(self.r["findings"]), 3)        # nothing from safe.py

    def test_safe_counterpart_not_flagged(self):
        from sbvf.sast.rules import scan_text
        safe = open(os.path.join(SAMPLES, "deser_py", "safe.py")).read()
        self.assertEqual([f.vuln for f in scan_text("safe.py", safe)], [])

    def test_metadata(self):
        f = next(x for x in self.r["findings"] if x["vuln"] == "insecure_deserialization")
        self.assertEqual((f["cwe"], f["severity"]), ("CWE-502", "high"))
        self.assertTrue(f["fix"] and f["impact"] and f["owner"] and f["exposure"] and f["how_in"])

    def test_streams_finding_steps(self):
        steps = []
        scan_path(os.path.join(SAMPLES, "deser_py"), on_step=steps.append)
        self.assertEqual(sum(1 for s in steps if s.kind == "finding"), 3)

    def _scan(self, name, code):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, name), "w") as fh:
                fh.write(code)
            return {f["vuln"] for f in scan_path(d)["findings"]}

    def test_python_variants(self):
        self.assertIn("insecure_deserialization", self._scan("a.py", "import pickle\nx = pickle.load(fh)\n"))
        self.assertIn("insecure_deserialization", self._scan("a.py", "import cPickle\nx = cPickle.loads(b)\n"))
        self.assertIn("insecure_deserialization", self._scan("a.py", "import marshal\nx = marshal.loads(b)\n"))
        self.assertIn("insecure_deserialization", self._scan("a.py", "import jsonpickle\nx = jsonpickle.decode(s)\n"))
        self.assertIn("insecure_deserialization", self._scan("a.py", "import yaml\nx = yaml.load(s)\n"))
        self.assertIn("insecure_deserialization", self._scan("a.py", "import yaml\nx = yaml.unsafe_load(s)\n"))
        self.assertIn("insecure_deserialization", self._scan("a.py", "import yaml\nx = yaml.load_all(s)\n"))
        for safe in ("import json\nx = json.loads(s)\n",
                     "import yaml\nx = yaml.safe_load(s)\n",
                     "import yaml\nx = yaml.safe_load_all(s)\n",
                     "import yaml\nx = yaml.load(s, Loader=yaml.SafeLoader)\n",
                     "import yaml\nx = yaml.load(s, Loader=yaml.BaseLoader)\n"):
            self.assertEqual(self._scan("a.py", safe), set(), safe)

    def test_php_variants(self):
        self.assertIn("insecure_deserialization", self._scan("a.php", "<?php $o = unserialize($_POST['d']);\n"))
        self.assertIn("insecure_deserialization", self._scan("a.php", "<?php $o = yaml_parse($data);\n"))
        for safe in ("<?php $o = json_decode($_POST['d'], true);\n",
                     "<?php $o = unserialize($d, ['allowed_classes' => false]);\n"):
            self.assertEqual(self._scan("a.php", safe), set(), safe)

    def test_js_variants(self):
        self.assertIn("insecure_deserialization",
                      self._scan("a.js", "const serialize = require('node-serialize');\nconst o = serialize.unserialize(p);\n"))
        for safe in ("const o = JSON.parse(p);\n",
                     "const o = serialize.serialize(p);\n",
                     # an unrelated in-house unserialize() must not be flagged
                     "const o = myCache.unserialize(row);\n"):
            self.assertEqual(self._scan("a.js", safe), set(), safe)

    def test_precision(self):
        from sbvf.sast.rules import scan_text
        # a method literally named *.unserialize on an unrelated object should not
        # drag in Python/PHP patterns, and JSON parsing is always safe
        self.assertNotIn("insecure_deserialization",
                         [f.vuln for f in scan_text("a.py", "data = json.loads(request.body)")])
        # yaml.loader attribute access (not a .load( call) is not a finding
        self.assertNotIn("insecure_deserialization",
                         [f.vuln for f in scan_text("a.py", "L = yaml.loader.SafeLoader")])

    def test_existing_samples_have_no_deser_findings(self):
        for name in os.listdir(SAMPLES):
            if name == "deser_py":
                continue
            r = scan_path(os.path.join(SAMPLES, name))
            self.assertFalse(
                [f for f in r["findings"] if f["vuln"] == "insecure_deserialization"], name)


class TestMishandledExceptions(unittest.TestCase):
    """OWASP A10: exception-handling pattern rules flag leaked error detail
    (CWE-209) and swallowed/overly broad handlers (CWE-390), not safe code."""

    def setUp(self):
        self.r = scan_path(os.path.join(SAMPLES, "errors_py"))
        self.src = open(os.path.join(SAMPLES, "errors_py", "app.py")).read().splitlines()

    def _line(self, needle):
        return next(i for i, l in enumerate(self.src, 1) if needle in l)

    def test_each_class_fires_on_vulnerable_code(self):
        got = _vulns(self.r)
        self.assertIn(("error_info_leak", self._line("jsonify(error=str(e))")), got)
        self.assertIn(("error_info_leak", self._line("traceback.format_exc()")), got)
        self.assertIn(("swallowed_exception", self._line("except:")), got)
        self.assertIn(("swallowed_exception", self._line("except Exception: pass")), got)

    def test_counts(self):
        vs = [v for v, _ in _vulns(self.r)]
        self.assertEqual((vs.count("error_info_leak"), vs.count("swallowed_exception")), (2, 2))
        self.assertSetEqual({v for v, _ in _vulns(self.r)},
                            {"error_info_leak", "swallowed_exception"})
        self.assertEqual(len(self.r["findings"]), 4)        # nothing from safe.py

    def test_safe_counterpart_not_flagged(self):
        from sbvf.sast.rules import scan_text
        safe = open(os.path.join(SAMPLES, "errors_py", "safe.py")).read()
        self.assertEqual([f.vuln for f in scan_text("safe.py", safe)], [])

    def test_metadata(self):
        f = {x["vuln"]: x for x in self.r["findings"]}
        self.assertEqual((f["error_info_leak"]["cwe"], f["error_info_leak"]["severity"]),
                         ("CWE-209", "medium"))
        self.assertEqual((f["swallowed_exception"]["cwe"], f["swallowed_exception"]["severity"]),
                         ("CWE-390", "low"))
        for x in f.values():
            self.assertTrue(x["fix"] and x["impact"] and x["owner"] and x["exposure"] and x["how_in"])

    def test_streams_finding_steps(self):
        steps = []
        scan_path(os.path.join(SAMPLES, "errors_py"), on_step=steps.append)
        self.assertEqual(sum(1 for s in steps if s.kind == "finding"), 4)

    def _scan(self, name, code):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, name), "w") as fh:
                fh.write(code)
            return {f["vuln"] for f in scan_path(d)["findings"]}

    def test_python_variants(self):
        self.assertIn("error_info_leak", self._scan("a.py", "def v():\n    return str(e)\n"))
        self.assertIn("error_info_leak", self._scan("a.py", "def v():\n    return jsonify(msg=str(exc))\n"))
        self.assertIn("swallowed_exception", self._scan("a.py", "try:\n    x()\nexcept:\n    pass\n"))
        self.assertIn("swallowed_exception", self._scan("a.py", "try:\n    x()\nexcept BaseException:\n    log()\n"))
        for safe in ("def v():\n    return jsonify(data=rows)\n",
                     "try:\n    x()\nexcept ValueError as e:\n    logger.error(str(e))\n    raise\n",
                     "try:\n    x()\nexcept ValueError:\n    return 'bad input', 400\n",
                     '"""return str(e) is only mentioned in this docstring."""\n'):
            self.assertEqual(self._scan("a.py", safe), set(), safe)

    def test_php_variants(self):
        self.assertIn("error_info_leak", self._scan("a.php", "<?php echo $e->getMessage();\n"))
        self.assertIn("error_info_leak", self._scan("a.php", "<?php die($ex->getMessage());\n"))
        self.assertIn("swallowed_exception", self._scan("a.php", "<?php try { x(); } catch (\\Exception $e) {}\n"))
        for safe in ("<?php echo 'something went wrong';\n",
                     "<?php try { x(); } catch (\\RuntimeException $e) { $log->error($e); }\n"):
            self.assertEqual(self._scan("a.php", safe), set(), safe)

    def test_js_variants(self):
        self.assertIn("error_info_leak", self._scan("a.js", "app.use((err, req, res, n) => { res.send(err.stack); });\n"))
        self.assertIn("error_info_leak", self._scan("a.js", "function h(err, res) { res.json({ error: err.message }); }\n"))
        self.assertIn("swallowed_exception", self._scan("a.js", "try { x(); } catch (e) {}\n"))
        self.assertIn("swallowed_exception", self._scan("a.js", "doThing().catch(() => {});\n"))
        for safe in ("function h(req, res) { res.send('internal error'); }\n",
                     "try { x(); } catch (e) { logger.error(e.stack); }\n",
                     "try { x(); } catch (e) { console.error(e); }\n"):
            self.assertEqual(self._scan("a.js", safe), set(), safe)

    def test_precision(self):
        from sbvf.sast.rules import scan_text
        # a plain, properly-handled broad catch is not flagged (only bare/BaseException/one-line-pass)
        self.assertNotIn("swallowed_exception",
                         {f.vuln for f in scan_text("a.py", "    except Exception:\n")})
        # logging the exception server-side is the safe form, not a leak
        self.assertNotIn("error_info_leak",
                         {f.vuln for f in scan_text("a.py", "    logger.error(str(e))\n")})
        # Flask's request.args is not an exception's .args (review regression)
        for line in ("    return jsonify(request.args)\n",
                     '    return make_response(request.args.get("q"), 200)\n'):
            self.assertNotIn("error_info_leak",
                             {f.vuln for f in scan_text("a.py", line)}, line)
        self.assertIn("error_info_leak",
                      {f.vuln for f in scan_text("a.py", "    return jsonify(detail=e.args)\n")})
        # a benign getMessage() on a non-exception receiver is not a leak (review regression)
        for line in ("    echo $user->getMessage();\n", "    echo $event->getMessage();\n"):
            self.assertNotIn("error_info_leak",
                             {f.vuln for f in scan_text("a.php", line)}, line)

    def test_existing_samples_have_no_a10_findings(self):
        a10 = {"error_info_leak", "swallowed_exception"}
        for name in os.listdir(SAMPLES):
            if name == "errors_py":
                continue
            r = scan_path(os.path.join(SAMPLES, name))
            self.assertFalse(
                [f for f in r["findings"] if f["vuln"] in a10], name)


class TestSupplyChain(unittest.TestCase):
    """OWASP A03: dependency-manifest checks flag unpinned versions (CWE-1104)
    and insecure sources (CWE-829), not pinned/caret specs over HTTPS."""

    def setUp(self):
        self.r = scan_path(os.path.join(SAMPLES, "supplychain"))

    def _pkg_line(self, needle):
        src = open(os.path.join(SAMPLES, "supplychain", "package.json")).read().splitlines()
        return next(i for i, l in enumerate(src, 1) if needle in l)

    def test_classes_fire_on_vulnerable_manifests(self):
        got = _vulns(self.r)
        self.assertIn(("unpinned_dependency", self._pkg_line('"lodash"')), got)
        self.assertIn(("unpinned_dependency", self._pkg_line('"legacy-widget"')), got)
        self.assertIn(("insecure_dependency_source", self._pkg_line('"internal-tool"')), got)

    def test_counts(self):
        vs = [v for v, _ in _vulns(self.r)]
        self.assertEqual(vs.count("unpinned_dependency"), 5)       # 3 npm + 2 pip
        self.assertEqual(vs.count("insecure_dependency_source"), 2)  # 1 npm + 1 pip
        self.assertEqual(len(self.r["findings"]), 7)

    def test_metadata(self):
        f = {x["vuln"]: x for x in self.r["findings"]}
        self.assertEqual((f["unpinned_dependency"]["cwe"], f["unpinned_dependency"]["severity"]),
                         ("CWE-1104", "low"))
        self.assertEqual((f["insecure_dependency_source"]["cwe"],
                          f["insecure_dependency_source"]["severity"]), ("CWE-829", "high"))
        for x in f.values():
            self.assertTrue(x["fix"] and x["impact"] and x["owner"] and x["exposure"] and x["how_in"])

    def test_streams_finding_steps(self):
        steps = []
        scan_path(os.path.join(SAMPLES, "supplychain"), on_step=steps.append)
        self.assertEqual(sum(1 for s in steps if s.kind == "finding"), 7)

    def _scan(self, name, content):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, name), "w") as fh:
                fh.write(content)
            return {f["vuln"] for f in scan_path(d)["findings"]}

    def test_npm_variants(self):
        self.assertIn("unpinned_dependency", self._scan("package.json", '{"dependencies":{"a":"*"}}'))
        self.assertIn("unpinned_dependency", self._scan("package.json", '{"dependencies":{"a":"latest"}}'))
        self.assertIn("unpinned_dependency", self._scan("package.json", '{"dependencies":{"a":"1.x"}}'))
        self.assertIn("unpinned_dependency", self._scan("package.json", '{"dependencies":{"a":">=1.0.0"}}'))
        self.assertIn("insecure_dependency_source", self._scan("package.json", '{"dependencies":{"a":"http://h/a.tgz"}}'))
        self.assertIn("insecure_dependency_source", self._scan("package.json", '{"dependencies":{"a":"git://h/a.git"}}'))
        # caret / tilde / exact / https are pinned-or-trusted — not flagged
        for safe in ('{"dependencies":{"a":"^4.17.21"}}',
                     '{"dependencies":{"a":"~1.2.3"}}',
                     '{"dependencies":{"a":"4.19.2"}}',
                     '{"dependencies":{"a":"git+https://github.com/me/r.git#v1"}}'):
            self.assertEqual(self._scan("package.json", safe), set(), safe)

    def test_composer_skips_platform_reqs(self):
        # php / ext-* are platform requirements, not packages
        got = self._scan("composer.json",
                         '{"require":{"php":"*","ext-json":"*","vendor/pkg":"1.2.3","bad/pkg":"*"}}')
        self.assertEqual(got, {"unpinned_dependency"})     # only bad/pkg, not php/ext-json

    def test_pip_variants(self):
        self.assertIn("unpinned_dependency", self._scan("requirements.txt", "requests>=2.0\n"))
        self.assertIn("unpinned_dependency", self._scan("requirements.txt", "pyyaml\n"))
        self.assertIn("insecure_dependency_source", self._scan("requirements.txt", "-e git+http://h/p.git#egg=p\n"))
        self.assertIn("insecure_dependency_source", self._scan("requirements.txt", "--index-url http://pypi.local/simple\n"))
        # == / ~= pins, https url, and comments are not flagged
        for safe in ("flask==2.3.3\n", "django~=4.2\n",
                     "requests @ https://example.com/r-2.0.tar.gz\n",
                     "--index-url https://pypi.local/simple\n", "# just a comment\n",
                     # a URL in a TRAILING comment is not the dependency source (review regression)
                     "requests==2.0  # see http://docs.example.com\n"):
            self.assertEqual(self._scan("requirements.txt", safe), set(), safe)
        # the comment must not hide a genuinely unpinned requirement either
        self.assertIn("unpinned_dependency", self._scan("requirements.txt", "pyyaml  # TODO pin\n"))

    def test_duplicate_dep_name_distinct_lines(self):
        # a dep named in two maps maps to two distinct lines (review regression)
        from sbvf.sast.supply_chain import _scan_json_manifest
        raw = ('{\n  "dependencies": { "lodash": "*" },\n'
               '  "devDependencies": { "lodash": "*" }\n}')
        lines = sorted(f.line for f in _scan_json_manifest("package.json", raw))
        self.assertEqual(len(lines), 2)
        self.assertNotEqual(lines[0], lines[1])

    def test_existing_samples_have_no_a03_findings(self):
        a03 = {"unpinned_dependency", "insecure_dependency_source"}
        for name in os.listdir(SAMPLES):
            if name == "supplychain":
                continue
            r = scan_path(os.path.join(SAMPLES, name))
            self.assertFalse(
                [f for f in r["findings"] if f["vuln"] in a03], name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
