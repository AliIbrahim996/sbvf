# SBVF — Third-party benchmark results

Measured by scanning **real, third-party vulnerable applications** (not SBVF's own
testbed) and checking how many of each app's *documented* vulnerability classes
SBVF reports. This is the independent counterpart to the self-graded in-repo
benchmark (`sbvf/sast/benchmark.py`).

**Reproduce:**

```bash
py -3.12 -m sbvf.sast.thirdparty_benchmark            # all apps
py -3.12 -m sbvf.sast.thirdparty_benchmark --only dsvw --json out.json
```

The harness shallow-clones each app, scans it with the normal engine, and deletes
the clone. It needs network access, so it is not part of CI.

## Results

**Run date:** 2026-11-26

| App | Commit | Stack | Documented classes | Found | Recall | Total findings |
|---|---|---|---|---|---|---|
| [DVNA](https://github.com/appsecco/dvna) | `9ba473add536` | Node / Express + EJS | 5 | 5 | **1.00** | 10 |
| [DSVW](https://github.com/stamparm/DSVW) | `9ca3c9acf3de` | Python (single file) | 6 | 6 | **1.00** | 15 |
| **Aggregate** | | | **11** | **11** | **1.00** | 25 |

- **DVNA** documented classes checked: SQL injection, command injection, code
  injection (math.js `eval` / `node-serialize` RCE), open redirect, XSS (EJS
  `<%- %>`).
- **DSVW** documented classes checked: SQL injection, command injection, code
  injection, path traversal, XSS, open redirect.

## What this measures (and what it does not)

- **Recall** is over each app's *documented* vulnerability classes: of the classes
  the app is known to contain, how many SBVF reports at least one finding for.
- **Precision is not claimed.** These apps are not exhaustively labelled, so a
  finding with no matching documented class may be a real, undocumented bug rather
  than a false positive. A precision number would require manual triage of every
  finding.
- "Total findings" is a rough noise signal, not a false-positive count.

## Planned additions

DVWA (PHP) and OWASP Juice Shop (TypeScript) as further targets, and a published
comparison against Semgrep OSS / SonarQube Community on the same apps.
