"""Statistics for the XSS scanner evaluation.

Produces:
  - Per-rule precision/recall/F1 with 95% bootstrap CIs on both datasets
  - McNemar tests between consecutive rules (A0→A1, A1→B, B→C)
  - Scan-time summary (RQ3)
"""

import sqlite3
import csv
import os
import sys
import statistics
import numpy as np
from scipy.stats import binomtest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.rules.a0 import RuleA0
from scanner.rules.a1 import RuleA1
from scanner.rules.b_context import RuleB
from scanner.rules.c_csp import RuleC


# ---------- Ground truth loaders ----------

def load_truth_lab():
    path = os.path.join(os.path.dirname(__file__), "..", "lab", "manifest.csv")
    with open(path, newline="", encoding="utf-8") as f:
        return {r["id"]: (r["actually_runs"] == "True") for r in csv.DictReader(f)}


def load_truth_benchmark():
    csv_path = r"C:\dev\BenchmarkJava\expectedresults-1.2.csv"
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    truth = {}
    for r in rows:
        norm = {k.strip(): (v or "").strip() for k, v in r.items() if k}
        if norm.get("category", "").lower() == "xss":
            truth[norm["# test name"]] = (
                norm.get("real vulnerability", "").lower() == "true"
            )
    return truth


# ---------- Rule evaluation ----------

def case_verdicts(rule, db_path, truth, key_field):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM captures").fetchall()
    con.close()

    case_flag = {}
    for r in rows:
        # Extract the short case ID (last path segment for lab, case_name for benchmark)
        if key_field == "case_name":
            cid = r["case_name"]
        else:
            cid = r["target_url"].split("/")[-1]  # e.g. 'case001'
        if cid not in truth:
            continue
        if case_flag.get(cid):
            continue
        v = rule.evaluate(dict(r))
        if v.exploitable:
            case_flag[cid] = True
        else:
            case_flag.setdefault(cid, False)

    case_ids = sorted(case_flag.keys())
    preds = [case_flag[c] for c in case_ids]
    truths = [truth[c] for c in case_ids]
    return case_ids, truths, preds


# ---------- Metrics ----------

def bootstrap_ci(preds, truths, metric, n_iter=5000, alpha=0.05):
    n = len(preds)
    if n == 0:
        return (0.0, 0.0)
    rng = np.random.default_rng(42)
    stats = []
    for _ in range(n_iter):
        idx = rng.integers(0, n, n)
        p = [preds[i] for i in idx]
        t = [truths[i] for i in idx]
        tp = sum(1 for pi, ti in zip(p, t) if pi and ti)
        fp = sum(1 for pi, ti in zip(p, t) if pi and not ti)
        fn = sum(1 for pi, ti in zip(p, t) if not pi and ti)
        if metric == "precision":
            stats.append(tp / (tp + fp) if (tp + fp) else 0.0)
        elif metric == "recall":
            stats.append(tp / (tp + fn) if (tp + fn) else 0.0)
        else:  # f1
            prec = tp / (tp + fp) if (tp + fp) else 0.0
            rec = tp / (tp + fn) if (tp + fn) else 0.0
            stats.append(2 * prec * rec / (prec + rec) if (prec + rec) else 0.0)
    lo = sorted(stats)[int(n_iter * (alpha / 2))]
    hi = sorted(stats)[int(n_iter * (1 - alpha / 2))]
    return lo, hi


def summarize(preds, truths):
    tp = sum(1 for p, t in zip(preds, truths) if p and t)
    fp = sum(1 for p, t in zip(preds, truths) if p and not t)
    fn = sum(1 for p, t in zip(preds, truths) if not p and t)
    tn = sum(1 for p, t in zip(preds, truths) if not p and not t)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    p_lo, p_hi = bootstrap_ci(preds, truths, "precision")
    r_lo, r_hi = bootstrap_ci(preds, truths, "recall")
    f_lo, f_hi = bootstrap_ci(preds, truths, "f1")
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": prec, "precision_ci": (p_lo, p_hi),
        "recall": rec, "recall_ci": (r_lo, r_hi),
        "f1": f1, "f1_ci": (f_lo, f_hi),
        "correct": [p == t for p, t in zip(preds, truths)],
    }


def mcnemar(a_correct, b_correct):
    b = sum(1 for x, y in zip(a_correct, b_correct) if x and not y)
    c = sum(1 for x, y in zip(a_correct, b_correct) if not x and y)
    n = b + c
    if n == 0:
        return 1.0, b, c
    p = binomtest(min(b, c), n, 0.5, alternative="two-sided").pvalue
    return p, b, c


def analyze(label, rule_objs, db_path, truth, key_field):
    results = {}
    for name, rule in rule_objs:
        _, truths, preds = case_verdicts(rule, db_path, truth, key_field)
        results[name] = summarize(preds, truths)

    n = len(next(iter(results.values()))["correct"])
    print(f"\n{'=' * 90}")
    print(f"  {label}  (n = {n} cases)")
    print(f"{'=' * 90}")
    print(f"{'Rule':<6} {'Precision [95% CI]':<32} {'Recall [95% CI]':<32} {'F1 [95% CI]':<30}")
    print("-" * 100)
    for name, r in results.items():
        p = f"{r['precision']:.3f} [{r['precision_ci'][0]:.3f}, {r['precision_ci'][1]:.3f}]"
        rc = f"{r['recall']:.3f} [{r['recall_ci'][0]:.3f}, {r['recall_ci'][1]:.3f}]"
        f = f"{r['f1']:.3f} [{r['f1_ci'][0]:.3f}, {r['f1_ci'][1]:.3f}]"
        print(f"{name:<6} {p:<32} {rc:<32} {f:<30}")

    print("\n  Pairwise McNemar tests (does the newer rule significantly change accuracy?):")
    names = [n for n, _ in rule_objs]
    for i in range(len(names) - 1):
        a, b = names[i], names[i + 1]
        p, b_only, c_only = mcnemar(results[a]["correct"], results[b]["correct"])
        sig = "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else "(ns)"
        print(f"    {a} vs {b}: p = {p:.4f} {sig}  "
              f"(only-{a}-right={b_only}, only-{b}-right={c_only})")


def timing(db_label, db_path):
    if not os.path.exists(db_path):
        return
    con = sqlite3.connect(db_path)
    times = [r[0] for r in con.execute("SELECT elapsed_ms FROM captures").fetchall()]
    con.close()
    if not times:
        return
    print(f"  {db_label:<12} n={len(times):<6} "
          f"median={statistics.median(times):.1f}ms  "
          f"mean={statistics.mean(times):.1f}ms  "
          f"p90={sorted(times)[int(len(times) * 0.9)]:.1f}ms")


def main():
    rules = [
        ("A0", RuleA0()),
        ("A1", RuleA1()),
        ("B", RuleB()),
        ("C", RuleC()),
    ]

    print("\n############ LAB ############")
    analyze(
        "LAB (49 cases)",
        rules,
        os.path.join(os.path.dirname(__file__), "..", "captures.db"),
        load_truth_lab(),
        key_field="target_url",
    )

    print("\n############ OWASP BENCHMARK ############")
    analyze(
        "OWASP BENCHMARK (455 XSS cases)",
        rules,
        os.path.join(os.path.dirname(__file__), "..", "captures_benchmark.db"),
        load_truth_benchmark(),
        key_field="case_name",
    )

    print("\n############ SCAN TIME (RQ3) ############")
    timing("Lab", os.path.join(os.path.dirname(__file__), "..", "captures.db"))
    timing("Benchmark", os.path.join(os.path.dirname(__file__), "..", "captures_benchmark.db"))


if __name__ == "__main__":
    main()