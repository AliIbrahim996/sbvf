"""Unit tests for the auth primitives (sbvf/store/auth.py).

Pure and stdlib-only: no database, no network, so they run in CI alongside the
core suites. The DB-backed user/session/scoping behaviour is covered in
tests/test_store.py (skipped without DATABASE_URL).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbvf.store import auth                                 # noqa: E402


class TestPasswordHashing(unittest.TestCase):
    def test_roundtrip(self):
        h = auth.hash_password("correct horse battery staple")
        self.assertTrue(auth.verify_password("correct horse battery staple", h))

    def test_wrong_password_fails(self):
        h = auth.hash_password("alpha-bravo-charlie")
        self.assertFalse(auth.verify_password("alpha-bravo-delta", h))

    def test_salt_is_random(self):
        a = auth.hash_password("orange-river-kite")
        b = auth.hash_password("orange-river-kite")
        self.assertNotEqual(a, b)                   # distinct salts -> distinct encodings
        self.assertTrue(auth.verify_password("orange-river-kite", a))
        self.assertTrue(auth.verify_password("orange-river-kite", b))

    def test_encoding_format(self):
        h = auth.hash_password("abcdefgh")
        parts = h.split("$")
        self.assertEqual(parts[0], "scrypt")
        self.assertEqual(len(parts), 6)            # scheme,n,r,p,salt,hash

    def test_malformed_stored_value_returns_false(self):
        for bad in ("", "garbage", "scrypt$only", "bcrypt$16384$8$1$x$y", None, 123):
            self.assertFalse(auth.verify_password("whatever", bad))

    def test_empty_password_rejected_on_hash(self):
        with self.assertRaises(ValueError):
            auth.hash_password("")


class TestSessionTokens(unittest.TestCase):
    def test_tokens_are_unique_and_urlsafe(self):
        t1, t2 = auth.new_session_token(), auth.new_session_token()
        self.assertNotEqual(t1, t2)
        self.assertTrue(len(t1) >= 32)

    def test_token_hash_deterministic_and_hides_token(self):
        t = auth.new_session_token()
        self.assertEqual(auth.token_hash(t), auth.token_hash(t))
        self.assertNotEqual(auth.token_hash(t), t)           # stored value != token
        self.assertEqual(len(auth.token_hash(t)), 64)        # sha256 hex


class TestFlag(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.get("SBVF_AUTH")
        os.environ.pop("SBVF_AUTH", None)

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("SBVF_AUTH", None)
        else:
            os.environ["SBVF_AUTH"] = self._saved

    def test_disabled_without_env(self):
        self.assertFalse(auth.auth_enabled())        # no SBVF_AUTH -> off

    def test_disabled_without_db_even_with_flag(self):
        os.environ["SBVF_AUTH"] = "1"
        # auth_enabled() requires BOTH the flag and a configured DB; without a
        # DATABASE_URL it must stay off so the single-user app is unchanged.
        if not auth.db.is_enabled():
            self.assertFalse(auth.auth_enabled())
        else:
            self.assertTrue(auth.auth_enabled())

    def test_truthy_values(self):
        for v in ("1", "true", "YES", "on"):
            os.environ["SBVF_AUTH"] = v
            self.assertEqual(auth.auth_enabled(), auth.db.is_enabled())
        for v in ("0", "false", "", "no"):
            os.environ["SBVF_AUTH"] = v
            self.assertFalse(auth.auth_enabled())


class TestValidation(unittest.TestCase):
    def test_username_rules(self):
        self.assertEqual(auth.username_problem("alice"), "")
        self.assertEqual(auth.username_problem("a.b-c_d@e"), "")
        self.assertTrue(auth.username_problem("ab"))             # too short
        self.assertTrue(auth.username_problem("has space"))      # invalid char
        self.assertTrue(auth.username_problem(None))

    def test_password_rules(self):
        self.assertEqual(auth.password_problem("longenough"), "")
        self.assertTrue(auth.password_problem("short"))
        self.assertTrue(auth.password_problem(None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
