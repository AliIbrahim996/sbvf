# SBVF — Search-Based Vulnerability Framework

Master's research prototype: a **search-based** framework that compares a Genetic
Algorithm (GA), Cuckoo Search (CS) and Random Search (RS) for detecting **XSS**,
**SQL Injection** and **Clickjacking** vulnerabilities in local web applications.

> Research title: *Design and Build a Search-Based Framework for Detecting Web
> Applications Vulnerabilities* — Tishreen University, Faculty of Informatics
> Engineering. Supervisor: Dr. Basel Hasan.

## Ethics & safety

All targets run on `127.0.0.1`. The framework **refuses non-local hosts** unless
`allow_remote=True` is passed explicitly for a target you are authorized to test.
The bundled apps are intentionally vulnerable and are for academic use only.

## Requirements

- Python 3.12 (standard library only for the core; **no pip install needed**).
- Optional: `selenium` for real-browser confirmation of XSS/Clickjacking.
- Optional: Docker, to run the dashboard and the DVWA practice lab.

## Quick start

Run the real-time dashboard (it starts the benchmark apps for you):

```bash
python -m ui.server
# open http://127.0.0.1:8080
```

Run the full experiment from the command line:

```bash
python -m sbvf.experiment --split test --runs 30 --budget 250 --out results
```

Run the test suite:

```bash
python -m tests.test_framework
```

## Docker

```bash
docker compose up sbvf                 # dashboard at http://localhost:8080
docker compose --profile labs up       # also starts DVWA at http://localhost:8081
```

## Layout

```
sbvf/        framework: individual, fitness, oracles, algorithms, stats, datasets, experiment
testbed/     intentionally-vulnerable apps (bank, blog, shop, wafapp) + launcher
ui/          real-time dashboard (SSE server + HTML)
tests/       unit + integration tests
docs/        thesis chapters (Arabic)
results/     generated CSV/JSON results
```

## Datasets

The benchmark endpoints are split (stratified) into `TRAIN` (parameter tuning) and
`TEST` (held-out, reported results) in `sbvf/datasets.py`, spanning an easy→hard
difficulty tier so the search's advantage (or lack of it) can be observed honestly.

## Metrics

- **Recall** on vulnerable endpoints and **false-positive rate** on safe endpoints.
- **Evals-to-first-detection** (efficiency), compared pairwise with the non-parametric
  **Mann-Whitney U** test and the **Vargha-Delaney Â12** effect size.
