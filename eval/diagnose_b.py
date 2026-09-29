import sqlite3
import csv
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.rules.a1 import RuleA1
from scanner.rules.b_context import RuleB


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

    a1 = RuleA1()
    b = RuleB()

    # Aggregate per case
    a1_flag, b_flag, b_reason = {}, {}, {}
    for r in rows:
        cid = r["target_url"].split("/")[-1]
        if cid not in truth:
            continue
        rd = dict(r)
        if a1.evaluate(rd).exploitable:
            a1_flag[cid] = True
        if b.evaluate(rd).exploitable:
            b_flag[cid] = True
            b_reason.setdefault(cid, b.evaluate(rd).reason)

    print("=== Cases where Rule B is WRONG but Rule A1 is RIGHT ===")
    print(f"{'case':<10} {'truth':<6} {'A1':<6} {'B':<6} B_reason")
    print("-" * 90)
    for cid in sorted(truth):
        t = truth[cid]
        a1v = a1_flag.get(cid, False)
        bv = b_flag.get(cid, False)
        if a1v == t and bv != t:
            print(f"{cid:<10} {str(t):<6} {str(a1v):<6} {str(bv):<6} {b_reason.get(cid, '')}")

    print("\n=== Cases where Rule B is RIGHT but Rule A1 is WRONG ===")
    for cid in sorted(truth):
        t = truth[cid]
        a1v = a1_flag.get(cid, False)
        bv = b_flag.get(cid, False)
        if a1v != t and bv == t:
            print(f"{cid:<10} {str(t):<6} {str(a1v):<6} {str(bv):<6} {b_reason.get(cid, '')}")

    print("\n=== Raw bodies for the WRONG cases ===")
    # Collect case IDs where B is wrong and A1 is right
    wrong_cases = [cid for cid in sorted(truth)
                   if a1_flag.get(cid, False) == truth[cid]
                   and b_flag.get(cid, False) != truth[cid]]
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    for cid in wrong_cases[:5]:
        print(f"\n--- {cid} ---")
        r = con.execute(
            "SELECT * FROM captures WHERE target_url LIKE ? LIMIT 1",
            (f"%{cid}",)
        ).fetchone()
        if r:
            print(f"PAYLOAD: {r['payload']!r}")
            print(f"TOKEN:   {r['token']!r}")
            print(f"BODY:    {r['body']!r}")
    con.close()


if __name__ == "__main__":
    main()