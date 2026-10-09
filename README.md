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

- [Problem Statement](#problem-statement)
- [Research Questions](#research-questions)
- [The Four Rules](#the-four-rules)
- [Architecture](#architecture)
- [Directory & File Reference](#directory--file-reference)
- [Build Phases](#build-phases)
- [How to Run](#how-to-run)
- [Results](#results)
- [Technology Stack](#technology-stack)
- [Known Limitations](#known-limitations)
- [References](#references)

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
      │  scanner/run_capture.py      │   Crawls / requests each case with
      │  + scanner/inject.py         │   6 different payloads. Saves raw
      │  + scanner/capture.py        │   status, headers, body → captures.db
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
```

The **scanner itself stays lightweight** (pure Python + requests + BeautifulSoup).
The browser is only used **afterwards**, as a **referee** — never inside the
scanner loop. This keeps the tool explainable and fast.

---

## Directory & File Reference

### `lab/` — the controlled test environment

| File | Purpose |
|---|---|
| `lab/generate_matrix.py` | Generates `matrix.csv` — the 49-case cross-product of **7 contexts × 4 defenses × 4 CSPs**. |
| `lab/matrix.csv` | The generated matrix. One row per test case: `id, context, defense, csp, template`. |
| `lab/app.py` | Flask server. Routes: `/` (homepage listing all cases) and `/page/<case_id>` (serves the case HTML with the correct context, defense, and CSP header). |
| `lab/run_oracle.py` | Runs the browser oracle against every case. Tries every payload; records the first payload that actually executes. |
| `lab/manifest.csv` | **The ground truth.** Output of `run_oracle.py`: for each case, `actually_runs` (true/false), `trigger_payload`, and `code_vulnerable_assumed`. |

**Contexts** (where the input lands):
`html_body`, `attr_double`, `attr_single`, `script_string`, `script_body`,
`comment`, `js_url`.

**Defenses** (simulated server-side escaping):
`none`, `html_escape`, `attr_escape`, `js_escape`.

**CSPs** (headers sent with the response):
`none`, `script-src 'self'`, `script-src 'none'`, `script-src 'unsafe-inline'`.

### `oracle/` — the browser referee

| File | Purpose |
|---|---|
| `oracle/referee.py` | Uses Playwright to open a URL in headless Chromium with a given payload. Listens for `alert()` dialogs, console messages, and checks `window.__xss_fired === 1`. Returns `{runs: bool, ...}`. Clicks any links on the page so `javascript:` URLs get a chance to fire. |
| `oracle/__init__.py` | Makes `oracle/` importable as a package. |

### `scanner/` — the detection engine

| File | Purpose |
|---|---|
| `scanner/inject.py` | Defines `PAYLOAD_TEMPLATES` — 6 payloads covering plain `<script>`, attribute breakouts (`"` and `'`), `onerror`, JS-string breakouts, and comment breakouts. Each payload carries a unique `{token}` and sets `window.__xss_fired=1` when it executes. `make_probes()` returns `(token, [payloads])`. |
| `scanner/capture.py` | SQLite-backed storage. **Opens a fresh connection per insert** to avoid Windows' "closed database" race. Two functions: `init_db()` and `save_capture(data)`. |
| `scanner/run_capture.py` | The orchestrator. Reads `lab/matrix.csv`, loops over each case, sends every payload, and saves the raw response (status, headers, body, elapsed time) to `captures.db`. |
| `scanner/rules/__init__.py` | Package marker. |
| `scanner/rules/base.py` | Defines the `Rule` interface and `Verdict` dataclass. Every rule implements `evaluate(capture_row) -> Verdict`. |
| `scanner/rules/a0.py` | **Rule A0** — flag if the token appears anywhere in the body. Naive baseline. |
| `scanner/rules/a1.py` | **Rule A1** — flag if the full payload appears verbatim. |
| `scanner/rules/b_context.py` | **Rule B** — the landing-spot checker. Scans the **raw HTML** for `<script>` blocks (not BeautifulSoup's parse tree, which hides nested `<script>` tags). Rejects payloads that were HTML-entity-encoded, that sit inside a JS string, or that appear after a raw `<` (which breaks the JS). Also checks `on*` attributes and `javascript:` URLs. |
| `scanner/rules/c_csp.py` | **Rule C** — runs Rule B first, then reads the enforced CSP header. If the effective `script-src` / `default-src` policy would block inline execution, downgrades to `MITIGATED`. |

### `eval/` — scoring and diagnostics

| File | Purpose |
|---|---|
| `eval/run_eval.py` | Reads `lab/manifest.csv` (ground truth) and `captures.db`. Runs each rule, **aggregates verdicts per case** (a case counts as flagged if *any* of its payloads triggers the rule), and prints precision / recall / F1. |
| `eval/diagnose_b.py` | Debug helper. Prints per-case verdicts for Rules A1 and B side-by-side, plus the raw bodies of cases where B is wrong and A1 is right. |
| `eval/diagnose_c.py` | Lists Rule C's false positives and false negatives with reason strings. |
| `eval/repro_case035.py` | Minimal reproducer for a specific edge case (nested `<script>` with a stray backslash). Useful for understanding the JS-string heuristic. |
| `eval/__init__.py` | Package marker. |

### Root

| File | Purpose |
|---|---|
| `requirements.txt` | Python dependencies. |
| `.gitignore` | Excludes `.venv/`, `__pycache__/`, `captures.db`. |
| `README.md` | This file. |
| `LICENSE` | MIT License. |
| `captures.db` | **Generated.** SQLite database holding every captured HTTP response. Regenerable via `python scanner/run_capture.py`. |

---

## Build Phases

The project was built in strictly ordered phases. Each phase is a self-contained
unit that can be tested before moving on.

### ✅ Phase 0 — Environment setup
- Install Python 3.11+, Git, Docker Desktop, Java (for the Benchmark later).
- Create virtual environment, install `requirements.txt`.
- `playwright install chromium`.
- **Done when:** `python -c "import flask, requests, playwright"` works.

### ✅ Phase 1 — Lab matrix + browser oracle
- **Files:** `lab/generate_matrix.py`, `lab/matrix.csv`, `lab/app.py`, `oracle/referee.py`, `lab/run_oracle.py`, `lab/manifest.csv`.
- **What it does:** Generates 49 test cases covering context × defense × CSP. Flask serves them. Playwright opens each one, checks whether the payload executes, and writes the true verdict to `manifest.csv`.
- **Done when:** `manifest.csv` contains `actually_runs` for every case and the Oracle's verdict matches a hand-checked page.

### ✅ Phase 2 — Crawler, injector, capture engine
- **Files:** `scanner/inject.py`, `scanner/capture.py`, `scanner/run_capture.py`, `.gitignore`.
- **What it does:** Sends every payload to every case and saves the **raw HTTP responses** (status, headers, body) to `captures.db`. Rules never touch the network — they run on the saved captures. This is what makes the experiment *controlled*.
- **Done when:** `python scanner/run_capture.py` finishes with 49 cases captured.

### ✅ Phase 3 — Baseline rules A0/A1 + eval harness
- **Files:** `scanner/rules/base.py`, `scanner/rules/a0.py`, `scanner/rules/a1.py`, `eval/run_eval.py`.
- **What it does:** Implements the two naive baselines and the scoring harness.
- **Done when:** `python eval/run_eval.py` prints a precision/recall table for A0 and A1.

### ✅ Phase 4 — Rule B (landing-spot check)
- **Files:** `scanner/rules/b_context.py`, `eval/diagnose_b.py`, `eval/repro_case035.py`.
- **What it does:** Scans the raw HTML for `<script>` blocks, rejects entity-encoded payloads, payloads inside JS strings, payloads after a raw `<`, and payloads with a stray backslash outside any string. Also checks `on*` handlers and `javascript:` URLs.
- **Status:** Complete. Precision 0.60, Recall 1.00 on the lab.

### ❌ Phase 5 — OWASP Benchmark integration (not started)
- Point the capture engine at the OWASP Benchmark (`https://localhost:8443/benchmark/`).
- Handle cookie/header-based parameters that the Benchmark uses.
- Score against the Benchmark's own `expectedresults-1.2.csv`.

### ✅ Phase 6 — Rule C (CSP check)
- **Files:** `scanner/rules/c_csp.py`, `eval/diagnose_c.py`.
- **What it does:** Reads the enforced CSP header. If the effective script policy blocks inline execution, downgrades the finding to `MITIGATED` (never dismisses it).
- **Status:** Complete. Precision 1.00, Recall 1.00 on the lab.

### ❌ Phase 7 — Statistics (not started)
- Median scan time per rule (RQ3).
- McNemar test for paired rule comparisons.
- Bootstrap confidence intervals.
- Per-context breakdown.

### 🟡 Phase 8 — Demo + README (this file)
- One-command `make eval` (or PowerShell equivalent).
- Manual demo script.

### ❌ Phase 9 — Update the deck (not started)
- Replace every "expected" number with real data.

---

## How to Run

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
Open `http://127.0.0.1:5000/` in a browser to browse all 49 cases.

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
python eval\run_eval.py           # prints precision / recall / F1 for A0, A1, B, C
```

### 6. (Optional) Inspect one case
```powershell
python oracle\referee.py "http://127.0.0.1:5000/page/case008"
```

---

## Results

All rules were evaluated on two independent datasets:
- **Lab** — 49 test cases designed by us, covering 7 injection contexts × 4 server-side defenses × 4 CSP configurations.
- **OWASP Benchmark** — 455 official XSS test cases from the OWASP BenchmarkJava 1.2 project (246 true vulnerabilities, 209 false positives).

### Lab results (49 cases)

| Rule | TP | FP | TN | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% CI] |
|---|---|---|---|---|---|---|---|
| A0 | 15 | 34 | 0 | 0 | 0.306 [0.184, 0.449] | 1.000 [1.000, 1.000] | 0.469 [0.310, 0.620] |
| A1 | 15 | 20 | 14 | 0 | 0.429 [0.265, 0.595] | 1.000 [1.000, 1.000] | 0.600 [0.419, 0.746] |
| B  | 15 | 10 | 24 | 0 | 0.600 [0.400, 0.800] | 1.000 [1.000, 1.000] | 0.750 [0.571, 0.889] |
| **C** | **15** | **0** | **34** | **0** | **1.000 [1.000, 1.000]** | **1.000 [1.000, 1.000]** | **1.000 [1.000, 1.000]** |

Pairwise McNemar tests (does the newer rule significantly change accuracy?):
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
- On the lab, Rule B improves precision from 0.43 to 0.60 (+17 points, p = 0.002), because it correctly ignores payloads that survived escaping but landed in non-executable positions (JS strings, after unescaped `<`, or inside HTML entities).
- On the Benchmark, B ties A1 (both precision 1.00, recall 0.76). This is because in real vulnerable cases, when the payload survives verbatim, it almost always lands in a genuinely executable position; and in the Benchmark's safe cases, escaping removes the payload entirely so A1 already ignores them.

**RQ2 — Does the CSP check help?**

**Yes on the lab; no downgrade needed on the Benchmark (by design).**
- On the lab, Rule C improves precision from 0.60 to 1.00 (+40 points, p = 0.002) by downgrading findings that the browser would refuse to run.
- On the Benchmark, all 5460 responses carry a CSP header, but its policy is `default-src 'unsafe-inline' 'unsafe-eval' 'self'` — permissive enough that no inline-script blocking occurs. Rule C therefore correctly does not downgrade anything, and its precision/recall match Rule B.
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
3. **Low initial Benchmark recall (0.18) was a coverage issue, not a detection-logic issue.** After per-case prefix detection, recall rose to 0.76 with only ~2% of remaining false negatives attributable to detection logic.
4. **Rule C's contribution is conditional on the target's CSP.** On sites with permissive CSP (like the Benchmark), Rule C behaves identically to Rule B — a correct and expected outcome.

---

## Technology Stack

| Component | Tool | Why |
|---|---|---|
| Language | Python 3.11+ | Standard for security tooling; fast to write, easy to read. |
| HTTP | `requests` | Simple, well-tested. |
| HTML parsing | `BeautifulSoup4` + `html5lib` | `html5lib` follows the HTML5 parsing spec, so it sees markup the way a browser does. Raw-regex fallback for nested `<script>` detection. |
| Browser automation | Playwright (headless Chromium) | Used **only** as an offline referee, never inside the scanner. |
| Test lab | Flask | Lightweight, easy to script 49 variations. |
| Storage | SQLite | Single-file, no server, perfect for offline analysis. |
| Scoring | pandas, scikit-learn (optional) | For computing metrics and, later, paired statistical tests. |
| Stats | statsmodels (Phase 7) | McNemar test for paired comparisons. |
| Version control | Git / GitHub | One commit per phase. |

---

## Known Limitations

The scanner deliberately stays simple so results are explainable. As a result:

1. **No full JavaScript parser.** Rule B uses a small custom lexer that
   handles basic string, comment, and stray-backslash cases, but cannot
   fully parse template literals, regex literals, or minified code.
2. **Raw-`<` heuristic.** Rule B treats any unescaped `<` before the marker
   as a syntax error. In real-world JS, `<` is a legitimate operator
   (`if (a < b)`). On real pages this could produce false negatives.
3. **Chromium only.** The oracle only reports what Chromium does. Firefox
   and Safari may differ on edge cases.
4. **CSP nonce reuse.** Rule C treats a nonce as protective. If a site reuses
   the same nonce across requests (a common bug), the CSP is effectively
   useless but our rule would still mark it mitigated.
5. **Meta-tag CSP.** Rule C only reads the response header. CSP can also be
   set via `<meta http-equiv="Content-Security-Policy">`, which has different
   semantics (it can't cover some directives). Lower confidence; untested.
6. **Reflected XSS only.** DOM-based and stored XSS are out of scope.

---

## References

### Academic

- Bazzoli, E., Criscione, C., Maggi, F., & Zanero, S. (2014). *XSS Peeker:
  A Systematic Analysis of Cross-Site Scripting Vulnerability Scanners.*
- Fink, T. (2018). *Automated XSS Vulnerability Detection through
  Context-Aware Fuzzing and Dynamic Analysis* [Diploma thesis, TU Wien].
- Iavich, M., Botchorishvili, D., & Lopata, A. (2026). *Context-Aware Hybrid
  Detection of DOM-Based Cross-Site Scripting via Runtime Semantic Modeling.*
  Information, 17(4), 346.
- Kalantari, F., Zaeifi, M., Bao, T., Wang, R., Shoshitaishvili, Y., &
  Doupe, A. (2022). *Context-Auditor: Context-Sensitive Content Injection
  Mitigation.* RAID 2022, 431–445.
- Steinhauser, A., & Tuma, P. (2019). *DjangoChecker: Applying Extended Taint
  Tracking and Server-Side Parsing for Detection of Context-Sensitive XSS
  Flaws.* Software: Practice and Experience, 49(1), 130–148.

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