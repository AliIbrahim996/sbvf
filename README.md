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

## Scanning a real open-source app

Point the framework at a real, locally-run open-source application (authorized local
testing only). It clones/downloads the project, launches it with the start command you
provide, crawls and tests it, then removes the clone:

```bash
python -m sbvf.scan_repo \
  --repo https://github.com/stamparm/DSVW \
  --start "python dsvw.py" \
  --base http://127.0.0.1:65412 \
  --endpoints /:id:sqli /:v:xss \
  --runs 15 --budget 60
```

The framework only talks to a local base URL; `--allow-remote` is required for anything
else and is intended solely for a local lab instance you are authorized to test.

### Bundled real-app targets (DVWA, OWASP Juice Shop)

```bash
docker compose --profile labs up -d dvwa juice-shop   # DVWA :8081, Juice Shop :3000
python -m sbvf.integrations --app all --runs 15 --budget 60
```

`sbvf/integrations.py` logs into DVWA (resets its DB, selects the "low" security level)
and targets Juice Shop's SQL-injectable product-search API. Observed result: the search
methods find the flaws in ~2 evaluations versus ~9–10 for the fixed-list Static baseline.

## Static source-code analysis (SAST)

Besides the dynamic, black-box search, SBVF ships a **static** analyzer that reads
a project's *source code*, detects the language and web framework, taint-tracks
untrusted user input from sources to dangerous sinks, and reports findings with
`file:line` precision. It never runs or contacts the application.

Supported stacks: **PHP** (native, Yii, Laravel) and **Python** (native, FastAPI,
Django). Detected classes include SQL injection, XSS, command/code injection,
file inclusion, path traversal and open redirect (each mapped to a CWE).

```bash
# scan a bundled sample, a local project, or clone-scan-remove a repo
python -m sbvf.scan_code testbed/sast_samples/php_laravel
python -m sbvf.scan_code path/to/project --json report.json
python -m sbvf.scan_code --repo https://github.com/user/project
```

Every step streams into the dashboard's **Static analysis** tab
(`python -m ui.server`, then the 🧬 tab). Six intentionally-vulnerable sample
projects live under `testbed/sast_samples/` (one per stack).

## Docker

```bash
docker compose up sbvf                 # dashboard at http://localhost:8080
docker compose --profile labs up       # also starts DVWA at http://localhost:8081
```

## Layout

```
sbvf/        framework: individual, fitness, oracles, algorithms, stats, datasets, experiment
sbvf/sast/   static analyzer: model, detect, php, python_analyzer, engine
testbed/     intentionally-vulnerable apps (bank, blog, shop, wafapp, authapp) + launcher
testbed/sast_samples/  vulnerable source projects for the static analyzer (6 stacks)
ui/          real-time dashboard (SSE server + HTML; dynamic + static tabs)
tests/       unit + integration tests (dynamic + static)
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
