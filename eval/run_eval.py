import sqlite3
import csv
import os
import sys
from scanner.rules.c_csp import RuleC

# This MUST come before importing anything from 'scanner'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.rules.a0 import RuleA0
from scanner.rules.a1 import RuleA1
from scanner.rules.b_context import RuleB


def load_ground_truth():
    """Reads lab/manifest.csv (the Oracle's verdict) as ground truth."""
    manifest_path = os.path.join(os.path.dirname(__file__), "..", "lab", "manifest.csv")
    truth = {}
    with open(manifest_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            truth[row["id"]] = (row["actually_runs"] == "True")
    return truth


def run_eval(rule, truth):
    db_path = os.path.join(os.path.dirname(__file__), "..", "captures.db")
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM captures").fetchall()
    con.close()

    # Aggregate: a case is flagged if ANY of its payload rows is flagged.
    case_flagged = {}
    for row in rows:
        case_id = row["target_url"].split("/")[-1]
        if case_id not in truth:
            continue
        if case_flagged.get(case_id):
            continue  # already flagged, no need to re-evaluate
        verdict = rule.evaluate(dict(row))
        if verdict.exploitable:
            case_flagged[case_id] = True
        else:
            case_flagged.setdefault(case_id, False)

    tp = fp = tn = fn = 0
    for case_id, pred in case_flagged.items():
        y_true = truth[case_id]
        if y_true and pred:           tp += 1
        elif not y_true and pred:     fp += 1
        elif not y_true and not pred: tn += 1
        elif y_true and not pred:     fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n--- {rule.name} (case-level, {len(case_flagged)} cases) ---")
    print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1:        {f1:.4f}")


if __name__ == "__main__":
    truth = load_ground_truth()
    run_eval(RuleA0(), truth)
    run_eval(RuleA1(), truth)
    run_eval(RuleB(), truth)
    run_eval(RuleC(), truth)   # <-- add this line