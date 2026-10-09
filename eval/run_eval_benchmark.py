import sqlite3
import csv
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.rules.a0 import RuleA0
from scanner.rules.a1 import RuleA1
from scanner.rules.b_context import RuleB
from scanner.rules.c_csp import RuleC

CSV_PATH = r"C:\dev\BenchmarkJava\expectedresults-1.2.csv"
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "captures_benchmark.db")


def load_ground_truth():
    """Returns {case_name: is_really_vulnerable} for XSS cases only."""
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    truth = {}
    for r in rows:
        norm = {}
        for k, v in r.items():
            if k is None:
                continue
            norm[k.strip()] = (v or "").strip()
        if norm.get("category", "").lower() == "xss":
            truth[norm["# test name"]] = (
                norm.get("real vulnerability", "").lower() == "true"
            )
    return truth


def run_eval(rule, truth):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM captures").fetchall()
    con.close()

    # Aggregate per case: flagged if ANY payload triggers the rule
    case_flagged = {}
    for r in rows:
        cid = r["case_name"]
        if cid not in truth:
            continue
        if case_flagged.get(cid):
            continue
        v = rule.evaluate(dict(r))
        if v.exploitable:
            case_flagged[cid] = True
        else:
            case_flagged.setdefault(cid, False)

    tp = fp = tn = fn = 0
    for cid, pred in case_flagged.items():
        y_true = truth[cid]
        if y_true and pred:           tp += 1
        elif not y_true and pred:     fp += 1
        elif not y_true and not pred: tn += 1
        elif y_true and not pred:     fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    print(f"\n--- {rule.name} (Benchmark XSS, {len(case_flagged)} cases) ---")
    print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1:        {f1:.4f}")


if __name__ == "__main__":
    truth = load_ground_truth()
    print(f"[*] Loaded {len(truth)} XSS cases from the Benchmark")
    print(f"[*] True vulnerabilities: {sum(truth.values())}")
    print(f"[*] False positives:      {len(truth) - sum(truth.values())}")

    run_eval(RuleA0(), truth)
    run_eval(RuleA1(), truth)
    run_eval(RuleB(), truth)
    run_eval(RuleC(), truth)