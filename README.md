# Reflected XSS Context-Aware Detection with CSP Mitigation

A lightweight, rule-based scanner that detects reflected Cross-Site Scripting (XSS)
by looking at **two things most scanners ignore**:

1. **Where the payload lands** in the response (the *landing spot*).
2. **What the site's Content Security Policy (CSP) allows** — so findings that
   the browser would block are reported as *mitigated*, not *exploitable*.

Built as a controlled experiment: same crawler, same payloads, same targets —
**only the decision rule changes**. This lets us measure exactly how much each
check contributes to accuracy.

---

## Table of Contents

- [Quick Start (One Command)](#quick-start-one-command)
- [Pipeline Orchestrator](#pipeline-orchestrator)
- [Manual Step-by-Step Run](#manual-step-by-step-run)
- [Problem Statement](#problem-statement)
- [Research Questions](#research-questions)
- [The Four Rules](#the-four-rules)
- [Architecture](#architecture)
- [Directory & File Reference](#directory--file-reference)
- [Build Phases](#build-phases)
- [Results](#results)
- [Technology Stack](#technology-stack)
- [Known Limitations](#known-limitations)
- [References](#references)

---

## Quick Start (One Command)

```powershell
cd "C:\Users\Ashad Shaikh\Desktop\XSS AND CSP Scanner"
.\.venv\Scripts\Activate.ps1
python run_pipeline.py
```

That's it. **One command runs the entire pipeline**: generates the lab, starts the
Flask server, captures HTTP responses, runs the browser oracle, evaluates all four
rules, and computes statistics. Roughly 2-3 minutes end-to-end on a laptop.

---

## Pipeline Orchestrator

The `run_pipeline.py` script at the project root runs every stage in order,
manages the Flask server lifecycle automatically, and prints progress. It accepts
three flags so you can skip stages you've already done.

### All Available Flags

| Flag | Effect | When to Use |
|---|---|---|
| *(none)* | Full lab pipeline: matrix → capture → oracle → eval → stats | First-time run, or after any code change |
| `--skip-capture` | Skip the HTTP capture stage (reuse existing `captures.db`) | When you've changed a rule but not the lab |
| `--skip-oracle` | Skip the browser oracle stage (reuse existing `manifest.csv`) | When you've changed a rule but not the lab |
| `--with-benchmark` | Also run the OWASP Benchmark pipeline (~40 min) | Before writing final results |
| `--skip-capture --skip-oracle` | Only re-run evaluation and statistics | Fastest iteration on a rule |

### Usage Examples

**Full lab pipeline (default, ~3 min):**
```powershell
python run_pipeline.py
```

**Fastest iteration — re-evaluate only, no network, no browser (~30 sec):**
```powershell
python run_pipeline.py --skip-capture --skip-oracle
```

**Full pipeline + OWASP Benchmark (~40 min):**
```powershell
python run_pipeline.py --with-benchmark
```

**Everything except re-capture (reuse DB, re-run oracle and evaluation):**
```powershell
python run_pipeline.py --skip-capture
```

### What Each Stage Does

| # | Stage | Command | Produces |
|---|---|---|---|
| 1 | Generate lab matrix | `python lab/generate_matrix.py` | `lab/matrix.csv` |
| 2 | Start Flask lab server | `python lab/app.py` (background) | — |
| 3 | Capture HTTP responses | `python scanner/run_capture.py` | `captures.db` |
| 4 | Run browser oracle | `python lab/run_oracle.py` | `lab/manifest.csv` |
| 5 | Evaluate rules A0/A1/B/C | `python eval/run_eval.py` | stdout (metrics) |
| 6 | Compute statistics | `python eval/stats.py` | stdout (CIs, McNemar) |
| 7 | Stop Flask server | *(cleanup)* | — |
| 8* | Benchmark capture | `python scanner/run_capture_benchmark.py` | `captures_benchmark.db` |
| 9* | Benchmark evaluation | `python eval/run_eval_benchmark.py` | stdout (metrics) |

Stages 8-9 run only with `--with-benchmark`.

### Why a Python Orchestrator (Not DVC)

We chose a plain Python script over DVC or Make for three reasons:

1. **Flask server lifecycle.** The capture stage needs a live HTTP server
   (`lab/app.py`). A Python orchestrator can start it, wait for it to be ready,
   run the stages, and stop it cleanly — DVC and Make cannot.
2. **Zero dependencies.** `run_pipeline.py` uses only the Python standard library.
   DVC adds ~200 MB to the virtual environment for a pipeline this size.
3. **Cross-platform.** Same command on Windows, macOS, and Linux. A Makefile
   would require additional tooling on Windows.

---

## Manual Step-by-Step Run

If you prefer to run stages individually (useful for debugging), here's how.

### 1. Install dependencies
```powershell
cd "C:\Users\Ashad Shaikh\Desktop\XSS AND CSP Scanner"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt --only-binary=:all:
python -m playwright install chromium
```

### 2. Generate the lab and start the server
```powershell
python lab\generate_matrix.py     # writes lab/matrix.csv
python lab\app.py                 # serves http://127.0.0.1:5000
```
Leave this terminal open. Open `http://127.0.0.1:5000/` in a browser to browse
all 49 cases.

### 3. Capture responses (in a second terminal)
```powershell
python scanner\run_capture.py     # writes captures.db
```

### 4. Run the browser oracle (ground truth)
```powershell
python lab\run_oracle.py          # writes lab/manifest.csv
```

### 5. Evaluate the rules
```powershell
python eval\run_eval.py           # precision / recall / F1 for A0, A1, B, C
python eval\stats.py              # 95% CIs and McNemar tests
```

### 6. (Optional) OWASP Benchmark
Start the Benchmark server (Docker is easiest):
```powershell
docker run --name owasp-benchmark --rm -d -p 8443:8443 kaakaww/owasp-benchmark
```
Then:
```powershell
python scanner\run_capture_benchmark.py
python eval\run_eval_benchmark.py
```

### 7. (Optional) Inspect one lab case directly
```powershell
python oracle\referee.py "http://127.0.0.1:5000/page/case008"
```

---

## Problem Statement

Reflected XSS is one of the most common bugs in websites. Simple scanners just ask:
*"Does my test code show up again in the response?"*

But:
- **Safely encoded text** can look identical to a real attack → **false alarms**.
- **CSP headers** can silently block the injection in the browser → **inflated severity**.

This project builds a small, explainable, rule-based checker that looks at
**landing spot** and **CSP** to reduce false positives without missing real bugs.

---

## Research Questions

**RQ1 — Landing-spot check.** Keeping everything else the same, how much does
checking *where* the payload lands cut false positives compared with only
checking that it reappears — and does it cost any real detections?

**RQ2 — CSP check.** On top of that, does reading the CSP further cut findings
that would not actually run in a browser — without hiding ones that would?

**RQ3 (optional) — Cost.** How much extra scan time does each rule add?

---

## The Four Rules

All rules operate on the **same captured data** (raw HTTP responses saved to disk).
They differ only in their decision logic.

| Rule | Name | Decision logic |
|---|---|---|
| **A0** | Token reappears | Flag if the unique token appears anywhere in the body. Naive baseline. |
| **A1** | Payload verbatim | Flag if the **full payload** appears verbatim. Stricter than A0. |
| **B** | Landing spot | Parse HTML like a browser. Flag only if the marker landed **inside `<script>` code** (not inside a JS string, not after a raw `<`), an **`on*` handler**, or a **`javascript:` URL** — and only if the payload wasn't HTML-entity-encoded. |
| **C** | CSP check | Run B first. If B flags, read the CSP header. If the policy would block that kind of inline execution, mark the finding **MITIGATED** instead of exploitable. |

**Key invariant (unit-tested):** Rule C only *downgrades* Rule B's findings.
It never introduces new findings.

---

## Architecture

```
         ┌──────────────────────┐
         │  lab/app.py (Flask)  │   Serves 49 test pages with
         │  http://localhost:5000│  different contexts, defenses, CSPs
         └──────────┬───────────┘
                    │
                    ▼
      ┌──────────────────────────────┐
      │  scanner/run_capture.py      │   Sends each case 6 different
      │  + scanner/inject.py         │   payloads. Saves raw status,
      │  + scanner/capture.py        │   headers, body → captures.db
      └──────────┬───────────────────┘
                 │
                 │  (offline, no network)
                 ▼
      ┌──────────────────────────────┐
      │  scanner/rules/{a0,a1,b,c}.py│   Run every rule against the SAME
      └──────────┬───────────────────┘   saved captures. Only the decision
                 │                        rule changes → controlled experiment.
                 ▼
      ┌──────────────────────────────┐
      │  eval/run_eval.py            │   Compares each rule's output with
      │  + lab/manifest.csv          │   the browser-oracle ground truth.
      └──────────────────────────────┘
                 │
                 ▼
          Precision / Recall / F1

       ┌──────────────────────────────┐
       │  oracle/referee.py           │   Independent judge: opens Chromium,
       │  (Playwright, headless)      │   checks whether the payload actually ran.
       └──────────────────────────────┘

       ┌──────────────────────────────┐
       │  run_pipeline.py             │   One command that runs everything
       │  (orchestrator)              │   in order with automatic cleanup.
       └──────────────────────────────┘
```

The **scanner itself stays lightweight** (pure Python + requests + BeautifulSoup).
The browser is only used **afterwards**, as a **referee** — never inside the
scanner loop. This keeps the tool explainable and fast.

---

## Directory & File Reference

### Root

| File | Purpose |
|---|---|
| `run_pipeline.py` | **One-command orchestrator.** Runs all stages with `--skip-capture`, `--skip-oracle`, `--with-benchmark` flags. |
| `requirements.txt` | Python dependencies. |
| `.gitignore` | Excludes `.venv/`, `__pycache__/`, `captures.db`, `captures_benchmark.db`. |
| `README.md` | This file. |
| `LICENSE` | MIT License. |
| `captures.db` | **Generated.** SQLite DB holding every lab HTTP response. Regenerated by `scanner/run_capture.py`. |
| `captures_benchmark.db` | **Generated.** Same for OWASP Benchmark. |

### `lab/` — the controlled test environment

| File | Purpose |
|---|---|
| `lab/generate_matrix.py` | Generates `matrix.csv` — the 49-case cross-product of **7 contexts × 4 defenses × 4 CSPs**. |
| `lab/matrix.csv` | The generated matrix. One row per test case. |
| `lab/app.py` | Flask server. Routes: `/` (homepage) and `/page/<case_id>` (serves the case with the correct context, defense, and CSP header). |
| `lab/run_oracle.py` | Runs the browser oracle against every case. Tries every payload; records the first payload that actually executes. |
| `lab/manifest.csv` | **Ground truth.** Output of `run_oracle.py`: `actually_runs` per case. |

**Contexts:** `html_body`, `attr_double`, `attr_single`, `script_string`,
`script_body`, `comment`, `js_url`.

**Defenses:** `none`, `html_escape`, `attr_escape`, `js_escape`.

**CSPs:** `none`, `script-src 'self'`, `script-src 'none'`, `script-src 'unsafe-inline'`.

### `oracle/` — the browser referee

| File | Purpose |
|---|---|
| `oracle/referee.py` | Uses Playwright to open a URL in headless Chromium with a payload. Listens for `alert()` and checks `window.__xss_fired === 1`. Returns `{runs: bool, ...}`. |
| `oracle/__init__.py` | Package marker. |

### `scanner/` — the detection engine

| File | Purpose |
|---|---|
| `scanner/inject.py` | 6 payload templates. Each carries a unique `{token}` and sets `window.__xss_fired=1` when it runs. |
| `scanner/capture.py` | SQLite-backed storage; opens a fresh connection per insert. |
| `scanner/run_capture.py` | **Lab capture.** Reads `lab/matrix.csv`, sends every payload, saves responses to `captures.db`. |
| `scanner/run_capture_benchmark.py` | **Benchmark capture.** Per-case prefix detection + 13-channel delivery. Saves to `captures_benchmark.db`. |
| `scanner/rules/__init__.py` | Package marker. |
| `scanner/rules/base.py` | `Rule` interface + `Verdict` dataclass. |
| `scanner/rules/a0.py` | Rule A0 — token appears anywhere. |
| `scanner/rules/a1.py` | Rule A1 — payload appears verbatim. |
| `scanner/rules/b_context.py` | Rule B — landing-spot check. Scans raw HTML for `<script>` blocks, rejects entity-encoded / in-JS-string / post-`<` payloads. |
| `scanner/rules/c_csp.py` | Rule C — reads enforced CSP header, downgrades findings the browser would block. |

### `eval/` — scoring and diagnostics

| File | Purpose |
|---|---|
| `eval/run_eval.py` | Lab evaluation. Aggregates verdicts per case; prints precision / recall / F1. |
| `eval/run_eval_benchmark.py` | Benchmark evaluation against `expectedresults-1.2.csv`. |
| `eval/stats.py` | Bootstrap 95% CIs and pairwise McNemar tests. |
| `eval/diagnose_b.py`, `eval/diagnose_c.py`, `eval/diagnose_benchmark.py` | Per-rule diagnostics; which cases are FPs / FNs and why. |
| `eval/peek_benchmark.py`, `eval/peek_csp.py` | Quick inspectors for the Benchmark CSV and CSP headers. |
| `eval/why_fn.py` | Classifies false negatives as detection-logic vs delivery issues. |
| `eval/repro_case035.py` | Minimal reproducer for a specific JS-string edge case. |

### `.github/workflows/`

| File | Purpose |
|---|---|
| `scan.yml` | GitHub Actions CI: reproduces the full lab pipeline on every push, and the Benchmark pipeline on manual trigger. |

---

## Build Phases

The project was built in strictly ordered phases. Each phase is a self-contained
unit that can be tested before moving on.

### ✅ Phase 0 — Environment setup
Python 3.11+, Git, Docker Desktop, Java, virtual environment, Playwright.

### ✅ Phase 1 — Lab matrix + browser oracle
`lab/` and `oracle/`. 49 test cases and a Playwright-based judge.

### ✅ Phase 2 — Crawler, injector, capture engine
`scanner/inject.py`, `scanner/capture.py`, `scanner/run_capture.py`. Saves raw HTTP responses for offline analysis — the reason the experiment is *controlled*.

### ✅ Phase 3 — Baseline rules A0/A1 + eval harness
`scanner/rules/a0.py`, `a1.py`, `eval/run_eval.py`.

### ✅ Phase 4 — Rule B (landing-spot check)
`scanner/rules/b_context.py`. Precision 0.60, Recall 1.00 on the lab.

### ✅ Phase 5 — OWASP Benchmark integration
`scanner/run_capture_benchmark.py`, `eval/run_eval_benchmark.py`, `eval/why_fn.py`.
455 XSS cases. Precision 1.00, Recall 0.76.

### ✅ Phase 6 — Rule C (CSP check)
`scanner/rules/c_csp.py`. Precision 1.00, Recall 1.00 on the lab.

### ✅ Phase 7 — Statistics
`eval/stats.py`. Bootstrap CIs and McNemar tests; all improvements on the lab
are statistically significant.

### ✅ Phase 8 — Pipeline orchestrator + README
`run_pipeline.py`, `.github/workflows/scan.yml`, this file.

### ⏳ Phase 9 — Update the presentation deck (manual)
Replace every "expected" number with real measured data.

---

## Results

All rules were evaluated on two independent datasets:
- **Lab** — 49 test cases designed by us, covering 7 injection contexts × 4 server-side defenses × 4 CSP configurations.
- **OWASP Benchmark** — 455 official XSS test cases from OWASP BenchmarkJava 1.2 (246 true vulnerabilities, 209 false positives).

### Lab results (49 cases)

| Rule | TP | FP | TN | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% CI] |
|---|---|---|---|---|---|---|---|
| A0 | 15 | 34 | 0 | 0 | 0.306 [0.184, 0.449] | 1.000 [1.000, 1.000] | 0.469 [0.310, 0.620] |
| A1 | 15 | 20 | 14 | 0 | 0.429 [0.265, 0.595] | 1.000 [1.000, 1.000] | 0.600 [0.419, 0.746] |
| B  | 15 | 10 | 24 | 0 | 0.600 [0.400, 0.800] | 1.000 [1.000, 1.000] | 0.750 [0.571, 0.889] |
| **C** | **15** | **0** | **34** | **0** | **1.000 [1.000, 1.000]** | **1.000 [1.000, 1.000]** | **1.000 [1.000, 1.000]** |

Pairwise McNemar tests:
- **A0 → A1:** p = 0.0001 (***)
- **A1 → B:**  p = 0.0020 (**)
- **B → C:**   p = 0.0020 (**)

### OWASP Benchmark results (455 cases)

| Rule | TP | FP | TN | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% CI] |
|---|---|---|---|---|---|---|---|
| A0 | 213 | 54 | 155 | 33 | 0.798 [0.749, 0.844] | 0.866 [0.822, 0.906] | 0.830 [0.794, 0.863] |
| A1 | 186 | 0 | 209 | 60 | **1.000 [1.000, 1.000]** | 0.756 [0.703, 0.810] | 0.861 [0.825, 0.895] |
| B  | 188 | 0 | 209 | 58 | **1.000 [1.000, 1.000]** | 0.764 [0.711, 0.817] | 0.866 [0.831, 0.899] |
| C  | 188 | 0 | 209 | 58 | **1.000 [1.000, 1.000]** | 0.764 [0.711, 0.817] | 0.866 [0.831, 0.899] |

Pairwise McNemar tests:
- **A0 → A1:** p = 0.0036 (**)
- A1 → B:  p = 0.5000 (ns)
- B → C:   p = 1.0000 (ns)

### Interpretation

**RQ1 — Does the landing-spot check help?**

**Yes on the lab, no measurable benefit on the Benchmark.**
- On the lab, Rule B improves precision from 0.43 to 0.60 (+17 points, p = 0.002), because it correctly ignores payloads that survived escaping but landed in non-executable positions.
- On the Benchmark, B ties A1 (both precision 1.00, recall 0.76). In real vulnerable cases, when the payload survives verbatim it almost always lands in a genuinely executable position; and in the Benchmark's safe cases, escaping removes the payload entirely so A1 already ignores them.

**RQ2 — Does the CSP check help?**

**Yes on the lab; no downgrade needed on the Benchmark (by design).**
- On the lab, Rule C improves precision from 0.60 to 1.00 (+40 points, p = 0.002) by downgrading findings that the browser would refuse to run.
- On the Benchmark, all 5460 responses carry a CSP header, but its policy is `default-src 'unsafe-inline' 'unsafe-eval' 'self'` — permissive enough that no inline-script blocking occurs. Rule C therefore correctly does not downgrade anything.
- **This is a positive finding:** Rule C's benefit is conditional on the site actually deploying a restrictive CSP. Our lab (`script-src 'self'` and `script-src 'none'`) demonstrates the impact when such a CSP is present.

**RQ3 — Scan-time cost**

| Dataset | Median | Mean | p90 |
|---|---|---|---|
| Lab | 16.3 ms | 14.1 ms | 26.1 ms |
| Benchmark | not measured per-request | — | — |

The lab scan adds no measurable time per case (all rules run on pre-captured responses, so decision-time is dominated by network I/O).

### Key takeaways for the paper

1. **Precision generalizes perfectly.** Rule C achieves 1.00 precision on both the controlled lab and the real-world OWASP Benchmark.
2. **Every pipeline step is a statistically significant improvement on the lab** (A0→A1: p=0.0001, A1→B: p=0.002, B→C: p=0.002).
3. **Low initial Benchmark recall (0.18) was a coverage issue, not a detection-logic issue.** After per-case prefix detection, recall rose to 0.76.
4. **Rule C's contribution is conditional on the target's CSP.** On sites with permissive CSP, Rule C behaves identically to Rule B — a correct and expected outcome.

---

## Technology Stack

| Component | Tool | Why |
|---|---|---|
| Language | Python 3.11+ | Standard for security tooling. |
| HTTP | `requests` | Simple, well-tested. |
| HTML parsing | `BeautifulSoup4` + `html5lib` | `html5lib` follows the HTML5 parsing spec. Raw-regex fallback for nested `<script>` detection. |
| Browser automation | Playwright (headless Chromium) | Used **only** as an offline referee. |
| Test lab | Flask | Lightweight, easy to script 49 variations. |
| Storage | SQLite | Single-file, no server, perfect for offline analysis. |
| Statistics | scipy, numpy | Bootstrap CIs, McNemar tests. |
| Orchestration | `run_pipeline.py` (stdlib only) | One command, zero dependencies. |
| CI | GitHub Actions | Auto-reproduce on push. |
| Version control | Git / GitHub | One commit per phase. |

---

## Known Limitations

The scanner deliberately stays simple so results are explainable. As a result:

1. **No full JavaScript parser.** Rule B uses a small custom lexer that handles basic string, comment, and stray-backslash cases, but cannot fully parse template literals, regex literals, or minified code.
2. **Raw-`<` heuristic.** Rule B treats any unescaped `<` before the marker as a syntax error. In real-world JS, `<` is a legitimate operator (`if (a < b)`). On real pages this could produce false negatives.
3. **Chromium only.** The oracle only reports what Chromium does. Firefox and Safari may differ on edge cases.
4. **CSP nonce reuse.** Rule C treats a nonce as protective. If a site reuses the same nonce across requests, the CSP is effectively useless but our rule would still mark it mitigated.
5. **Meta-tag CSP.** Rule C only reads the response header. CSP via `<meta http-equiv>` is lower confidence; untested.
6. **Reflected XSS only.** DOM-based and stored XSS are out of scope.
7. **Benchmark recall ceiling.** 24% of Benchmark XSS cases require an input channel our simplified crawler doesn't reach (uncommon header names, complex session flows). Improving this requires a production-grade crawler, not better detection logic.

---

## References

### Academic

- Bazzoli, E., Criscione, C., Maggi, F., & Zanero, S. (2014). *XSS Peeker: A Systematic Analysis of Cross-Site Scripting Vulnerability Scanners.*
- Fink, T. (2018). *Automated XSS Vulnerability Detection through Context-Aware Fuzzing and Dynamic Analysis* [Diploma thesis, TU Wien].
- Iavich, M., Botchorishvili, D., & Lopata, A. (2026). *Context-Aware Hybrid Detection of DOM-Based Cross-Site Scripting via Runtime Semantic Modeling.* Information, 17(4), 346.
- Kalantari, F., Zaeifi, M., Bao, T., Wang, R., Shoshitaishvili, Y., & Doupe, A. (2022). *Context-Auditor: Context-Sensitive Content Injection Mitigation.* RAID 2022, 431–445.
- Steinhauser, A., & Tuma, P. (2019). *DjangoChecker: Applying Extended Taint Tracking and Server-Side Parsing for Detection of Context-Sensitive XSS Flaws.* Software: Practice and Experience, 49(1), 130–148.

### Tools & specifications

- OWASP Benchmark Project — https://github.com/OWASP-Benchmark/BenchmarkJava
- OWASP Juice Shop — https://owasp.org/www-project-juice-shop/
- OWASP ZAP — https://www.zaproxy.org/
- XSStrike — https://github.com/s0md3v/XSStrike
- MDN: Content Security Policy — https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- CSP Level 3 — https://www.w3.org/TR/CSP3/
- PortSwigger Web Security Academy — https://portswigger.net/web-security

---

## Intended Use

This tool is intended for **authorized security testing and academic research only**.
Do not use it against systems you do not own or do not have explicit written
permission to test. The authors accept no liability for misuse.

---

## License

MIT License. See `LICENSE` for details.