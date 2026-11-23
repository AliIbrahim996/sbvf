"""Train/test split of the benchmark endpoints.

To avoid the methodological objection that algorithm parameters were tuned on the
same cases used to report results, the labelled endpoints are partitioned into:

  TRAIN : used by `tune.py` to choose GA/CS hyper-parameters.
  TEST  : held out; final results in the thesis are reported on these only.

The split is stratified so every vulnerability class and both labels
(vulnerable/safe) appear in each partition.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Endpoint:
    path: str
    param: str | None
    vuln: str
    label: str      # "vulnerable" | "safe"
    app: str        # which application it belongs to


# Benchmark built from the bundled testbed app plus the extra apps in testbed/apps/.
ALL = [
    # --- core testbed (app "bank") ---
    Endpoint("/xss/reflect_raw", "q", "xss", "vulnerable", "bank"),
    Endpoint("/xss/reflect_lt", "q", "xss", "vulnerable", "bank"),
    Endpoint("/xss/attr", "q", "xss", "vulnerable", "bank"),
    Endpoint("/xss/safe", "q", "xss", "safe", "bank"),
    Endpoint("/sqli/error", "name", "sqli", "vulnerable", "bank"),
    Endpoint("/sqli/blind", "name", "sqli", "vulnerable", "bank"),
    Endpoint("/sqli/safe", "name", "sqli", "safe", "bank"),
    Endpoint("/clickjacking/vuln", None, "clickjacking", "vulnerable", "bank"),
    Endpoint("/clickjacking/safe", None, "clickjacking", "safe", "bank"),
    # --- extra app "blog" (stored-style reflected + filtered) ---
    Endpoint("/search", "term", "xss", "vulnerable", "blog"),
    Endpoint("/greet", "user", "xss", "vulnerable", "blog"),
    Endpoint("/comment_safe", "text", "xss", "safe", "blog"),
    Endpoint("/login", "user", "sqli", "vulnerable", "blog"),
    Endpoint("/profile_safe", "id", "sqli", "safe", "blog"),
    Endpoint("/embed", None, "clickjacking", "vulnerable", "blog"),
    # --- extra app "shop" (stronger but imperfect filters) ---
    Endpoint("/find", "kw", "xss", "vulnerable", "shop"),
    Endpoint("/note", "msg", "xss", "safe", "shop"),
    Endpoint("/item", "sku", "sqli", "vulnerable", "shop"),
    Endpoint("/order_safe", "oid", "sqli", "safe", "shop"),
    Endpoint("/panel", None, "clickjacking", "safe", "shop"),
    # --- hard app "wafapp" (WAF-style blacklists; the hard tier) ---
    Endpoint("/xss_hard", "q", "xss", "vulnerable", "wafapp"),
    Endpoint("/sqli_hard", "sku", "sqli", "vulnerable", "wafapp"),
    Endpoint("/xss_safe_hard", "q", "xss", "safe", "wafapp"),
    # --- access-control app "authapp" (IDOR + RBAC) ---
    Endpoint("/idor/account", "id", "idor", "vulnerable", "authapp"),
    Endpoint("/idor/doc", "id", "idor", "vulnerable", "authapp"),
    Endpoint("/idor/account_safe", "id", "idor", "safe", "authapp"),
    Endpoint("/idor/doc_safe", "id", "idor", "safe", "authapp"),
    Endpoint("/rbac/admin", None, "rbac", "vulnerable", "authapp"),
    Endpoint("/rbac/dashboard", None, "rbac", "vulnerable", "authapp"),
    Endpoint("/rbac/admin_safe", None, "rbac", "safe", "authapp"),
    Endpoint("/rbac/report_safe", None, "rbac", "safe", "authapp"),
]


def _stratified_split(items, test_fraction=0.5):
    """Split deterministically by (vuln,label) strata, alternating to each side."""
    train, test = [], []
    buckets: dict[tuple, list] = {}
    for e in items:
        buckets.setdefault((e.vuln, e.label), []).append(e)
    for key in sorted(buckets):
        group = buckets[key]
        for i, e in enumerate(group):
            (test if i % 2 == 0 else train).append(e)
    return train, test


TRAIN, TEST = _stratified_split(ALL)


def by_app(app: str):
    return [e for e in ALL if e.app == app]
