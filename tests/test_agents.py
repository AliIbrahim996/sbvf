"""Tests for the optional AI-agents layer (sbvf/agents/).

No network: a FakeProvider returns canned JSON. The DB-backed runner test is
skipped unless DATABASE_URL points at a reachable PostgreSQL (same convention as
tests/test_store.py).
"""
from __future__ import annotations

import os
import unittest

from sbvf.agents import provider as prov
from sbvf.agents.base import AgentError, run_json
from sbvf.agents.finders import PrioritizationAgent, TriageAgent
from sbvf.agents.provider import LLMProvider


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


if __name__ == "__main__":
    unittest.main()
