"""Experiment runner: runs every algorithm on every benchmark endpoint for N seeds,
collects metrics, runs statistical tests and writes JSON + CSV results.

Metrics per run:
  - confirmed        : whether the vulnerability was confirmed
  - evals_to_first   : evaluations until first confirmation (efficiency)
  - best_fitness     : best fitness reached
  - total_evals      : evaluations consumed

The benchmark is dataset-aware (sbvf/datasets.py) and supports a train/test split.
Run records can be streamed to a callback for live UIs.

Usage:
    python -m sbvf.experiment --split test --runs 30 --budget 200
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys

from .algorithms import ALGORITHMS, ALL_METHODS
from .oracles import Oracle, Target
from . import datasets, stats


def iter_runs(endpoints, base_urls, runs, budget, allow_remote=False, on_run=None):
    """Yield one record per (endpoint, algorithm, seed). Calls on_run(record) first."""
    for e in endpoints:
        for alg_name, alg in ALGORITHMS.items():
            for seed in range(runs):
                target = Target(base_urls[e.app], allow_remote=allow_remote)
                oracle = Oracle(target, e.path, e.param, e.vuln)
                res = alg(oracle, budget, seed)
                rec = {
                    "app": e.app, "endpoint": e.path, "vuln": e.vuln, "label": e.label,
                    "algorithm": alg_name, "seed": seed,
                    "confirmed": int(res.confirmed),
                    "evals_to_first": res.evals_to_first if res.evals_to_first else "",
                    "best_fitness": round(res.best_fitness, 4),
                    "total_evals": res.total_evals,
                    "requests": target.requests,
                    "best_payload": res.best_payload,
                }
                if on_run:
                    on_run(rec)
                yield rec


def run_suite(endpoints, base_urls, runs, budget, out_dir, allow_remote=False,
              on_run=None):
    os.makedirs(out_dir, exist_ok=True)
    rows = list(iter_runs(endpoints, base_urls, runs, budget, allow_remote, on_run))
    _write_csv(rows, os.path.join(out_dir, "runs.csv"))
    report = analyze(rows)
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    _print_summary(report)
    return report


def _write_csv(rows, path):
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def analyze(rows):
    algs = sorted({r["algorithm"] for r in rows})
    report = {"per_algorithm": {}, "detection_on_vulnerable": {},
              "false_positives_on_safe": {}, "efficiency_tests": []}

    for alg in algs:
        vuln_rows = [r for r in rows if r["algorithm"] == alg and r["label"] == "vulnerable"]
        safe_rows = [r for r in rows if r["algorithm"] == alg and r["label"] == "safe"]
        recall = sum(r["confirmed"] for r in vuln_rows) / len(vuln_rows) if vuln_rows else 0
        fp = sum(r["confirmed"] for r in safe_rows) / len(safe_rows) if safe_rows else 0
        report["detection_on_vulnerable"][alg] = round(recall, 4)
        report["false_positives_on_safe"][alg] = round(fp, 4)

    by_vuln = {}
    for r in rows:
        if r["label"] != "vulnerable" or not r["confirmed"]:
            continue
        by_vuln.setdefault(r["endpoint"], {}).setdefault(r["algorithm"], []).append(
            int(r["evals_to_first"]))

    for endpoint, data in by_vuln.items():
        for a, b in [("GA", "RS"), ("CS", "RS"), ("GA", "CS")]:
            if a in data and b in data and data[a] and data[b]:
                u, p = stats.mann_whitney_u(data[a], data[b])
                a12 = stats.vargha_delaney_a12(data[a], data[b])
                report["efficiency_tests"].append({
                    "endpoint": endpoint, "compare": f"{a} vs {b}",
                    "median_a": stats.summary(data[a])["median"],
                    "median_b": stats.summary(data[b])["median"],
                    "p_value": round(p, 4), "a12": round(a12, 3),
                    "effect": stats.effect_label(a12), "significant": p < 0.05,
                })
    return report


def budget_sweep(endpoints, base_urls, budgets, runs, out_dir, methods=None,
                 allow_remote=False):
    """Recall as a function of evaluation budget, per method, across seeds.

    This is the informative view: at small budgets recall is well below 100% and the
    methods separate; raising the budget lets every method saturate. It directly
    answers "is a flat 100% just overfitting?" -- no, it is budget saturation, and the
    curve below saturation is where the real differences live.

    The Static baseline is deterministic, so it is run once per budget (seed ignored).
    """
    methods = methods or ALL_METHODS
    vuln = [e for e in endpoints if e.label == "vulnerable"]
    rows = []
    for e in vuln:
        for name, method in methods.items():
            seeds = [0] if name == "Static" else range(runs)
            for budget in budgets:
                for seed in seeds:
                    t = Target(base_urls[e.app], allow_remote=allow_remote)
                    o = Oracle(t, e.path, e.param, e.vuln)
                    r = method(o, budget, seed)
                    rows.append({"endpoint": e.path, "vuln": e.vuln, "method": name,
                                 "budget": budget, "seed": seed,
                                 "confirmed": int(r.confirmed),
                                 "evals_to_first": r.evals_to_first or ""})
    os.makedirs(out_dir, exist_ok=True)
    _write_csv(rows, os.path.join(out_dir, "sweep.csv"))

    # recall[method][budget] = detected vulnerable runs / total
    curve = {}
    for name in methods:
        curve[name] = {}
        for budget in budgets:
            sub = [r for r in rows if r["method"] == name and r["budget"] == budget]
            curve[name][budget] = round(sum(r["confirmed"] for r in sub) / len(sub), 3) if sub else 0.0
    with open(os.path.join(out_dir, "sweep.json"), "w", encoding="utf-8") as f:
        json.dump({"budgets": budgets, "recall_by_method": curve}, f, indent=2)

    print("\n=== Recall vs budget (detection rate on vulnerable endpoints) ===")
    print("budget   " + "".join(f"{m:>9}" for m in methods))
    for budget in budgets:
        print(f"{budget:>6}   " + "".join(f"{curve[m][budget]:>8.0%} " for m in methods))
    return curve


def _print_summary(report):
    print("\n=== Detection rate (Recall) on vulnerable endpoints ===")
    for alg, v in report["detection_on_vulnerable"].items():
        print(f"  {alg}: {v:.1%}")
    print("\n=== False-positive rate on safe endpoints ===")
    for alg, v in report["false_positives_on_safe"].items():
        print(f"  {alg}: {v:.1%}")
    print("\n=== Efficiency (evals-to-first), pairwise ===")
    for t in report["efficiency_tests"]:
        flag = "*" if t["significant"] else " "
        print(f" {flag} {t['endpoint']:<22} {t['compare']:<9} "
              f"med {t['median_a']:>5} vs {t['median_b']:>5}  "
              f"p={t['p_value']:.3f}  A12={t['a12']:.2f} ({t['effect']})")


SPLITS = {"train": lambda: datasets.TRAIN,
          "test": lambda: datasets.TEST,
          "all": lambda: datasets.ALL}


def main(argv=None):
    from testbed.launcher import start_all, stop_all
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=list(SPLITS), default="all")
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--budget", type=int, default=200)
    ap.add_argument("--out", default="results")
    ap.add_argument("--sweep", help="comma-separated budgets, e.g. 10,25,50,100,200")
    args = ap.parse_args(argv)

    endpoints = SPLITS[args.split]()
    servers, base_urls = start_all()
    try:
        if args.sweep:
            budgets = [int(x) for x in args.sweep.split(",")]
            budget_sweep(endpoints, base_urls, budgets, args.runs,
                         os.path.join(args.out, args.split + "_sweep"))
        else:
            run_suite(endpoints, base_urls, args.runs, args.budget,
                      os.path.join(args.out, args.split))
    finally:
        stop_all(servers)


if __name__ == "__main__":
    sys.exit(main())
