import sqlite3
import csv
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.rules.c_csp import RuleC


def load_truth():
    path = os.path.join(os.path.dirname(__file__), "..", "lab", "manifest.csv")
    with open(path, newline="", encoding="utf-8") as f:
        return {r["id"]: (r["actually_runs"] == "True") for r in csv.DictReader(f)}


def main():
    truth = load_truth()
    db_path = os.path.join(os.path.dirname(__file__), "..", "captures.db")
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM captures").fetchall()
    con.close()

    rule = RuleC()
    case_flag = {}
    case_reason = {}
    for r in rows:
        cid = r["target_url"].split("/")[-1]
        if cid not in truth:
            continue
        v = rule.evaluate(dict(r))
        if v.exploitable:
            case_flag[cid] = True
            case_reason.setdefault(cid, v.reason)
        else:
            case_flag.setdefault(cid, False)

    print("=== Rule C FALSE POSITIVES (flagged, but Oracle says safe) ===")
    print(f"{'case':<10} {'reason':<70}")
    print("-" * 90)
    for cid in sorted(truth):
        if case_flag.get(cid) and not truth[cid]:
            print(f"{cid:<10} {case_reason.get(cid, '')[:70]}")

    print("\n=== Rule C FALSE NEGATIVES (missed, but Oracle says exploitable) ===")
    for cid in sorted(truth):
        if not case_flag.get(cid) and truth[cid]:
            print(f"{cid:<10}")


if __name__ == "__main__":
    main()