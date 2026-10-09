import sqlite3
import csv
import os

CSV_PATH = r"C:\dev\BenchmarkJava\expectedresults-1.2.csv"
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "captures_benchmark.db")

# Load ground truth
with open(CSV_PATH, newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))
truth = {}
for r in rows:
    n = {k.strip(): (v or "").strip() for k, v in r.items() if k}
    if n.get("category", "").lower() == "xss":
        truth[n["# test name"]] = n.get("real vulnerability", "").lower() == "true"

con = sqlite3.connect(DB_PATH)
con.row_factory = sqlite3.Row

# For each case: did the token ever appear in ANY response body?
print(f"{'case':<22} {'truth':<6} {'n_rows':<7} {'any_token':<10} {'any_payload':<12} {'statuses':<15} {'body_len_sample'}")
print("-" * 110)

fns_with_token = 0
fns_without_token = 0
fn_examples_with = []
fn_examples_without = []

for cid in sorted(truth.keys()):
    case_rows = con.execute(
        "SELECT * FROM captures WHERE case_name = ?", (cid,)
    ).fetchall()
    if not case_rows:
        continue
    any_token = any(r["token"] in r["body"] for r in case_rows)
    any_payload = any(r["payload"] in r["body"] for r in case_rows)
    statuses = set(r["status"] for r in case_rows)
    body_lens = sorted(set(len(r["body"]) for r in case_rows))

    if truth[cid] and not any_payload:
        # This is a false negative
        if any_token:
            fns_with_token += 1
            fn_examples_with.append(cid)
        else:
            fns_without_token += 1
            fn_examples_without.append(cid)

    # Print first 40 rows for readability
    if len(fn_examples_with) + len(fn_examples_without) <= 40:
        print(f"{cid:<22} {str(truth[cid]):<6} {len(case_rows):<7} {str(any_token):<10} {str(any_payload):<12} {str(statuses):<15} {body_lens}")

print()
print("=== FALSE NEGATIVE ANALYSIS ===")
print(f"FNs where token appeared (but not full payload): {fns_with_token}")
print(f"FNs where token did NOT appear at all:          {fns_without_token}")
print()
if fn_examples_with:
    print(f"Examples where token is present (detection-logic issue): {fn_examples_with[:5]}")
if fn_examples_without:
    print(f"Examples where token is absent  (delivery issue):       {fn_examples_without[:5]}")

con.close()