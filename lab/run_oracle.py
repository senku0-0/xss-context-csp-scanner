import csv, asyncio, sys, os, uuid

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from oracle.referee import check
from scanner.inject import PAYLOAD_TEMPLATES


async def main():
    matrix_path = os.path.join(os.path.dirname(__file__), "matrix.csv")
    with open(matrix_path, newline="", encoding="utf-8") as f:
        cases = list(csv.DictReader(f))

    results = []
    for i, case in enumerate(cases, 1):
        url = f"http://127.0.0.1:5000/page/{case['id']}"
        print(f"[{i}/{len(cases)}] Oracle on {case['id']}...", end=" ", flush=True)

        token = uuid.uuid4().hex[:8]
        payloads = [p.format(token=token) for p in PAYLOAD_TEMPLATES]
        any_runs = False
        trigger_payload = ""
        for payload in payloads:
            res = await check(url, payload=payload)
            if res["runs"]:
                any_runs = True
                trigger_payload = payload
                break

        case["actually_runs"] = any_runs
        case["trigger_payload"] = trigger_payload
        case["code_vulnerable_assumed"] = (case["defense"] == "none")
        results.append(case)
        print("RUNS" if any_runs else "safe")

    out_path = os.path.join(os.path.dirname(__file__), "manifest.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"\n[+] Wrote ground truth to {out_path}")


if __name__ == "__main__":
    asyncio.run(main())