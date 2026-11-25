"""Tests for the optional AI-agents layer (sbvf/agents/).

No network: a FakeProvider returns canned JSON. The DB-backed runner test is
skipped unless DATABASE_URL points at a reachable PostgreSQL (same convention as
tests/test_store.py).
"""
from __future__ import annotations

import os
import unittest

from sbvf.agents import provider as prov
from sbvf.agents import retrieval
from sbvf.agents.base import AgentError, run_json
from sbvf.agents.finders import PrioritizationAgent, TriageAgent
from sbvf.agents.provider import LLMProvider
from sbvf.agents.qa import QAAgent


class FakeProvider(LLMProvider):
    """Scripted provider: returns canned JSON based on the prompt, no network."""

    name = "fake"

    def __init__(self, scripted=None):
        self.model = "fake-model"
        self._scripted = scripted  # optional list of responses, consumed in order

    def complete(self, system, user, *, max_tokens=1024):
        if self._scripted is not None:
            return self._scripted.pop(0)
        if "Triage" in user:
            return '{"is_false_positive": false, "confidence": 0.9, "rationale": "reachable sink"}'
        if "remediation" in user:
            return '```json\n{"summary": "Parameterize", "remediation": "Use bound params."}\n```'
        if "Prioritise" in user or "prioritise" in user.lower():
            return '{"summary": "one critical injection", "ranking": [{"idx": 0, "risk_score": 95, "reason": "RCE"}]}'
        return "{}"


_FINDING = {
    "vuln": "sqli", "title": "SQL Injection", "cwe": "CWE-89", "severity": "critical",
    "location": "shop/item.php:12", "file": "shop/item.php", "line": 12,
    "framework": "php-native", "source": "$_GET['id']", "sink": "mysqli_query",
    "param": "id", "method": "GET", "how_in": "taint flows in", "code": "mysqli_query($q)",
}


class TestProviderResolution(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in
                       ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OLLAMA_URL", "SBVF_AI_PROVIDER")}
        for k in self._saved:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_disabled_when_nothing_configured(self):
        self.assertFalse(prov.is_enabled())
        self.assertEqual(prov.available_providers(), [])
        self.assertIsNone(prov.get_provider())

    def test_claude_preferred_when_several_set(self):
        os.environ["OPENAI_API_KEY"] = "x"
        os.environ["ANTHROPIC_API_KEY"] = "y"
        self.assertTrue(prov.is_enabled())
        self.assertEqual(prov.available_providers()[0], "claude")
        self.assertEqual(prov.get_provider().name, "claude")

    def test_explicit_override_and_env_force(self):
        os.environ["OPENAI_API_KEY"] = "x"
        os.environ["ANTHROPIC_API_KEY"] = "y"
        self.assertEqual(prov.get_provider("openai").name, "openai")
        os.environ["SBVF_AI_PROVIDER"] = "openai"
        self.assertEqual(prov.get_provider().name, "openai")

    def test_unconfigured_name_returns_none(self):
        os.environ["ANTHROPIC_API_KEY"] = "y"
        self.assertIsNone(prov.get_provider("openai"))  # requested but not configured


class TestJsonParsing(unittest.TestCase):
    def test_strips_code_fences(self):
        p = FakeProvider(scripted=['```json\n{"a": 1}\n```'])
        self.assertEqual(run_json(p, "s", "u"), {"a": 1})

    def test_extracts_json_amid_prose(self):
        p = FakeProvider(scripted=['Sure! Here you go: {"a": 2} — hope that helps'])
        self.assertEqual(run_json(p, "s", "u"), {"a": 2})

    def test_retries_once_then_succeeds(self):
        p = FakeProvider(scripted=["not json at all", '{"ok": true}'])
        self.assertEqual(run_json(p, "s", "u"), {"ok": True})
        self.assertEqual(p._scripted, [])  # both responses consumed

    def test_raises_after_two_failures(self):
        p = FakeProvider(scripted=["nope", "still nope"])
        with self.assertRaises(AgentError):
            run_json(p, "s", "u")


class TestAgentNormalize(unittest.TestCase):
    def test_triage_clamps_and_coerces(self):
        agent = TriageAgent(FakeProvider())
        out = agent.normalize({"is_false_positive": 1, "confidence": 5, "rationale": "x"})
        self.assertIs(out["is_false_positive"], True)
        self.assertEqual(out["confidence"], 1.0)  # clamped to [0,1]

    def test_prioritization_fills_missing_indices(self):
        agent = PrioritizationAgent(FakeProvider())
        out = agent.normalize({"summary": "s", "ranking": [{"idx": 1, "risk_score": 200}]}, count=3)
        idxs = sorted(r["idx"] for r in out["ranking"])
        self.assertEqual(idxs, [0, 1, 2])             # every finding present exactly once
        top = next(r for r in out["ranking"] if r["idx"] == 1)
        self.assertEqual(top["risk_score"], 100.0)    # clamped to [0,100]


class TestQaRetrieval(unittest.TestCase):
    def test_rank_findings_orders_by_overlap(self):
        findings = [
            {"title": "XSS", "vuln": "xss", "message": "", "cwe": "CWE-79"},
            {"title": "SQL Injection", "vuln": "sqli", "message": "sql", "cwe": "CWE-89"},
            {"title": "Open Redirect", "vuln": "open_redirect", "message": "", "cwe": "CWE-601"},
        ]
        ranked = retrieval.rank_findings(findings, "which scans had sql injection?")
        self.assertEqual(ranked[0]["vuln"], "sqli")

    def test_query_terms_drops_stopwords(self):
        self.assertEqual(retrieval.query_terms("what are my scans with SQL injection"),
                         ["sql", "injection"])

    def test_qa_agent_returns_prose_unchanged(self):
        p = FakeProvider(scripted=["Scan #1 found SQL injection at shop/item.php:12."])
        answer = QAAgent(p).ask("where is the sqli?", "context here")
        self.assertIn("SQL injection", answer)


class TestSearchClause(unittest.TestCase):
    def test_terms_and_where_are_parameterized(self):
        from sbvf.store import repository
        cols = ["title", "message", "file", "vuln", "cwe"]
        terms = repository._search_terms("which scans had SQL injection?")
        self.assertEqual(terms, ["which", "scans", "had", "sql", "injection"])
        where, params = repository._search_where(["sql", "injection"], cols)
        self.assertTrue(where.startswith(" WHERE "))
        self.assertEqual(where.count("ILIKE %s"), 2 * len(cols))  # 2 terms x 5 cols
        self.assertEqual(len(params), 2 * len(cols))
        self.assertTrue(all(p == "%sql%" or p == "%injection%" for p in params))

    def test_empty_query_yields_no_clause(self):
        from sbvf.store import repository
        self.assertEqual(repository._search_where([], ["title"]), ("", []))


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL not set")
class TestRunnerPersistence(unittest.TestCase):
    def setUp(self):
        from sbvf.store import db, migrate
        db.reset_for_tests()
        migrate.init()

    def test_run_persists_assessments_and_prioritization(self):
        from sbvf.agents import runner
        from sbvf.store import repository
        result = {"root": "testbed", "frameworks": {"php": "php-native"},
                  "files_scanned": 1, "counts": {}, "findings": [_FINDING]}
        scan_id = repository.save_scan(result, target="t", scan_type="sample")
        self.assertIsNotNone(scan_id)

        orig = runner.get_provider
        runner.get_provider = lambda name=None: FakeProvider()  # inject, no network
        try:
            out = runner.run_finding_agents(scan_id)
        finally:
            runner.get_provider = orig

        self.assertTrue(out["ok"])
        ai = repository.get_ai(scan_id)
        self.assertEqual(len(ai["assessments"]), 1)
        self.assertIn(ai["assessments"][0]["is_false_positive"], (False,))
        self.assertIsNotNone(ai["prioritization"])
        self.assertTrue(ai["prioritization"]["summary"])
        repository.delete_scan(scan_id)

    def test_answer_question_persists_chat(self):
        from sbvf.agents import runner
        from sbvf.store import repository
        result = {"root": "testbed", "frameworks": {"php": "php-native"},
                  "files_scanned": 1, "counts": {}, "findings": [_FINDING]}
        scan_id = repository.save_scan(result, target="t", scan_type="sample")

        orig = runner.get_provider
        runner.get_provider = lambda name=None: FakeProvider(scripted=["It had SQL injection."])
        try:
            out = runner.answer_question("which scans had sql injection?")
        finally:
            runner.get_provider = orig

        self.assertTrue(out["ok"])
        self.assertIn("SQL injection", out["answer"])
        chat = repository.list_chat(scan_id=None)
        roles = [m["role"] for m in chat[-2:]]
        self.assertEqual(roles, ["user", "assistant"])
        repository.delete_scan(scan_id)


class TestSendCodeSwitch(unittest.TestCase):
    """The offending code line is sent to the LLM only when SBVF_AI_SEND_CODE is on."""

    def setUp(self):
        self._orig = os.environ.pop("SBVF_AI_SEND_CODE", None)

    def tearDown(self):
        if self._orig is None:
            os.environ.pop("SBVF_AI_SEND_CODE", None)
        else:
            os.environ["SBVF_AI_SEND_CODE"] = self._orig

    def _brief(self):
        from sbvf.agents.finders import _finding_brief
        return _finding_brief({"title": "Hardcoded secret", "cwe": "CWE-798",
                               "severity": "high", "location": "a.py:1",
                               "source": "literal", "sink": "assignment",
                               "code": 'API_KEY = "***"'})

    def test_code_withheld_by_default(self):
        self.assertNotIn("Offending line", self._brief())

    def test_code_included_when_enabled(self):
        os.environ["SBVF_AI_SEND_CODE"] = "1"
        brief = self._brief()
        self.assertIn("Offending line", brief)
        self.assertIn('API_KEY = "***"', brief)


if __name__ == "__main__":
    unittest.main()
