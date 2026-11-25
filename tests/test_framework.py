"""Unit and integration tests for SBVF.

Runnable with either pytest or plain `python -m tests.test_framework`.
The integration tests start the testbed in a background thread on a free port.
"""
import os
import random
import sys
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbvf import fitness, stats                              # noqa: E402
from sbvf.individual import GRAMMARS, Individual, crossover  # noqa: E402
from sbvf.algorithms import ALGORITHMS                       # noqa: E402
from sbvf.oracles import Oracle, Target                      # noqa: E402
from sbvf.sast import scan_path, derive_endpoints, extract_routes  # noqa: E402
import testbed.app as app                                    # noqa: E402
import testbed.apps.authapp as authapp                        # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestIndividual(unittest.TestCase):
    def test_render_within_grammar(self):
        rng = random.Random(0)
        for _ in range(50):
            ind = Individual.random("xss", rng)
            self.assertIsInstance(ind.render(), str)

    def test_crossover_preserves_length(self):
        rng = random.Random(1)
        a = Individual.random("sqli", rng)
        b = Individual.random("sqli", rng)
        c1, c2 = crossover(a, b, rng)
        self.assertEqual(len(c1.genome), len(a.genome))
        self.assertEqual(len(c2.genome), len(b.genome))

    def test_mutation_stays_in_bounds(self):
        rng = random.Random(2)
        ind = Individual.random("xss", rng)
        for _ in range(100):
            ind.mutate(rng, pm=1.0)
            self.assertTrue(0 <= ind.genome[1] < len(GRAMMARS["xss"]["core"]))


class TestFitness(unittest.TestCase):
    def test_xss_confirmed_on_raw_reflection(self):
        payload = "<script>alert(1)</script>"
        fit, conf = fitness.xss_fitness(payload, f"<p>{payload}</p>")
        self.assertEqual(fit, 1.0)
        self.assertTrue(conf)

    def test_xss_zero_when_escaped(self):
        fit, conf = fitness.xss_fitness("<script>alert(1)</script>",
                                        "<p>&lt;script&gt;</p>")
        self.assertFalse(conf)
        self.assertLess(fit, 1.0)

    def test_clickjacking_protected(self):
        fit, conf = fitness.clickjacking_fitness({"X-Frame-Options": "DENY"})
        self.assertEqual(fit, 0.0)
        self.assertFalse(conf)

    def test_clickjacking_vulnerable(self):
        fit, conf = fitness.clickjacking_fitness({})
        self.assertTrue(conf)

    def test_idor_confirmed_on_other_owner(self):
        fit, conf = fitness.idor_fitness("owner=u2 secret=x", 200, my_token="u1")
        self.assertEqual(fit, 1.0)
        self.assertTrue(conf)

    def test_idor_not_confirmed_on_own_record(self):
        fit, conf = fitness.idor_fitness("owner=u1 secret=x", 200, my_token="u1")
        self.assertFalse(conf)

    def test_idor_forbidden_is_dead_end(self):
        fit, conf = fitness.idor_fitness("forbidden", 403, my_token="u1")
        self.assertEqual(fit, 0.0)
        self.assertFalse(conf)

    def test_rbac_confirmed_on_admin_content(self):
        fit, conf = fitness.rbac_fitness("ADMIN_ONLY dashboard", 200)
        self.assertTrue(conf)

    def test_rbac_forbidden_not_confirmed(self):
        fit, conf = fitness.rbac_fitness("forbidden", 403)
        self.assertFalse(conf)

    def test_missing_auth_public_endpoint_confirmed(self):
        fit, conf = fitness.missing_auth_fitness("owner=u2 secret=x", 200)
        self.assertEqual(fit, 1.0)
        self.assertTrue(conf)

    def test_missing_auth_unauthorized_not_confirmed(self):
        for status in (401, 403):
            fit, conf = fitness.missing_auth_fitness("forbidden", status)
            self.assertEqual(fit, 0.0)
            self.assertFalse(conf)

    def test_missing_auth_login_redirect_not_confirmed(self):
        fit, conf = fitness.missing_auth_fitness("", 302)
        self.assertFalse(conf)

    def test_missing_auth_login_prompt_body_not_confirmed(self):
        # A 200 that is actually a login page, not the protected data.
        fit, conf = fitness.missing_auth_fitness("<p>login required</p>", 200)
        self.assertFalse(conf)

    def test_missing_auth_benign_200_not_confirmed(self):
        # Reachable with no auth but carries nothing sensitive -> not a finding.
        fit, conf = fitness.missing_auth_fitness("<p>home</p>", 200)
        self.assertFalse(conf)

    def test_missing_auth_sensitive_data_wins_over_nav_login_link(self):
        # Data served with no auth is public even if the page has a 'Sign in' nav link.
        body = "<nav><a href='/login'>Sign in</a></nav><p>owner=u2 secret=x</p>"
        fit, conf = fitness.missing_auth_fitness(body, 200)
        self.assertEqual(fit, 1.0)
        self.assertTrue(conf)


class TestStats(unittest.TestCase):
    def test_a12_symmetry(self):
        a, b = [5, 6, 7, 8], [1, 2, 3, 4]
        self.assertAlmostEqual(stats.vargha_delaney_a12(a, b), 1.0)
        self.assertAlmostEqual(stats.vargha_delaney_a12(b, a), 0.0)

    def test_identical_no_significance(self):
        a = [3, 3, 3, 3, 3]
        _, p = stats.mann_whitney_u(a, list(a))
        self.assertGreater(p, 0.05)


class TestIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.H)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()
        time.sleep(0.2)
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_target_rejects_remote(self):
        with self.assertRaises(ValueError):
            Target("http://example.com")

    def test_ga_finds_raw_xss(self):
        t = Target(self.base)
        o = Oracle(t, "/xss/reflect_raw", "q", "xss")
        res = ALGORITHMS["GA"](o, budget=200, seed=0)
        self.assertTrue(res.confirmed)

    def test_no_false_positive_on_safe_xss(self):
        t = Target(self.base)
        o = Oracle(t, "/xss/safe", "q", "xss")
        res = ALGORITHMS["GA"](o, budget=200, seed=0)
        self.assertFalse(res.confirmed)

    def test_sqli_error_detected(self):
        t = Target(self.base)
        o = Oracle(t, "/sqli/error", "name", "sqli")
        res = ALGORITHMS["CS"](o, budget=200, seed=0)
        self.assertTrue(res.confirmed)

    def test_sqli_safe_clean(self):
        t = Target(self.base)
        o = Oracle(t, "/sqli/safe", "name", "sqli")
        res = ALGORITHMS["RS"](o, budget=200, seed=0)
        self.assertFalse(res.confirmed)

    def test_clickjacking_vuln_vs_safe(self):
        t = Target(self.base)
        self.assertTrue(ALGORITHMS["RS"](
            Oracle(t, "/clickjacking/vuln", None, "clickjacking"), 10, 0).confirmed)
        self.assertFalse(ALGORITHMS["RS"](
            Oracle(t, "/clickjacking/safe", None, "clickjacking"), 10, 0).confirmed)


class TestAccessControl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), authapp.H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_idor_vulnerable_detected(self):
        o = Oracle(Target(self.base), "/idor/account", "id", "idor")
        self.assertTrue(ALGORITHMS["GA"](o, 200, 0).confirmed)

    def test_idor_safe_clean(self):
        o = Oracle(Target(self.base), "/idor/account_safe", "id", "idor")
        self.assertFalse(ALGORITHMS["RS"](o, 200, 0).confirmed)

    def test_rbac_missing_check_detected(self):
        o = Oracle(Target(self.base), "/rbac/admin", None, "rbac")
        self.assertTrue(ALGORITHMS["RS"](o, 50, 0).confirmed)

    def test_rbac_tampering_detected(self):
        o = Oracle(Target(self.base), "/rbac/dashboard", None, "rbac")
        self.assertTrue(ALGORITHMS["GA"](o, 200, 0).confirmed)

    def test_rbac_safe_clean(self):
        o = Oracle(Target(self.base), "/rbac/admin_safe", None, "rbac")
        self.assertFalse(ALGORITHMS["CS"](o, 200, 0).confirmed)

    def test_missing_auth_public_endpoint_detected(self):
        # /idor/account never checks the token, so it serves a secret with no auth.
        o = Oracle(Target(self.base), "/idor/account", "id", "missing_auth")
        self.assertTrue(ALGORITHMS["GA"](o, 200, 0).confirmed)

    def test_missing_auth_owner_scoped_endpoint_clean(self):
        # /idor/account_safe requires ownership, so an anonymous caller gets 403.
        o = Oracle(Target(self.base), "/idor/account_safe", "id", "missing_auth")
        self.assertFalse(ALGORITHMS["RS"](o, 200, 0).confirmed)

    def test_missing_auth_login_required_endpoint_clean(self):
        # /rbac/admin returns 401 without a token -> not a public endpoint.
        o = Oracle(Target(self.base), "/rbac/admin", None, "missing_auth")
        self.assertFalse(ALGORITHMS["RS"](o, 50, 0).confirmed)

    def test_missing_auth_does_not_use_supplied_session(self):
        # Even with a valid session cookie, the public-endpoint probe drops it, so a
        # properly protected endpoint is not misreported as public.
        o = Oracle(Target(self.base, cookies={"token": "u1"}),
                   "/idor/account_safe", "id", "missing_auth")
        self.assertFalse(ALGORITHMS["RS"](o, 200, 0).confirmed)


class TestSastToDynamicBridge(unittest.TestCase):
    """The static->dynamic bridge turns an IDOR finding into search-ready endpoints."""

    SAMPLE = os.path.join(_ROOT, "testbed", "sast_samples", "idor_django")

    def test_idor_bridges_to_idor_and_missing_auth(self):
        res = scan_path(self.SAMPLE)
        routes = extract_routes(self.SAMPLE)
        eps, skipped = derive_endpoints(res["findings"], routes=routes)
        self.assertEqual(sorted({e.vuln for e in eps}), ["idor", "missing_auth"])
        for e in eps:                         # both drive the recovered path-segment route
            self.assertEqual(e.where, "path")
            self.assertIn("__SBVF__", e.path_template or "")
            self.assertEqual(e.param, "order_id")

    def test_non_http_class_stays_static_only(self):
        finding = {"vuln": "weak_crypto", "param": "", "method": "GET",
                   "framework": "python", "file": "x.py", "location": "x.py:1",
                   "function": ""}
        eps, skipped = derive_endpoints([finding])
        self.assertEqual(eps, [])
        self.assertEqual(len(skipped), 1)
        self.assertIn("not dynamically confirmable", skipped[0]["reason"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
