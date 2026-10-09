import csv
import os
import sys
import json
import time
import sqlite3
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.inject import make_probes

requests.packages.urllib3.disable_warnings()

BENCHMARK_BASE = "https://localhost:8443/benchmark"
CSV_PATH = r"C:\dev\BenchmarkJava\expectedresults-1.2.csv"
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "captures_benchmark.db")

# All XSS subdirectories in the Benchmark. Each test case lives in exactly one.
XSS_PREFIXES = [
    "xss-00", "xss-01", "xss-02", "xss-03", "xss-04",
    "xss-05", "xss-06", "xss-07", "xss-08", "xss-09",
]

FIELD_SUFFIXES = ["", "Area", "Answer", "Form"]


def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("DROP TABLE IF EXISTS captures")
        con.execute("""
            CREATE TABLE captures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_name TEXT,
                prefix TEXT,
                target_url TEXT,
                param TEXT,
                payload TEXT,
                token TEXT,
                method TEXT,
                status INTEGER,
                headers TEXT,
                body TEXT,
                elapsed_ms REAL
            )
        """)


def save_capture(d):
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            INSERT INTO captures
            (case_name, prefix, target_url, param, payload, token, method,
             status, headers, body, elapsed_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            d["case_name"], d["prefix"], d["target_url"], d["param"],
            d["payload"], d["token"], d["method"], d["status"],
            json.dumps(d["headers"]), d["body"], d["elapsed_ms"]
        ))


def load_xss_cases():
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        norm = {k.strip(): (v or "").strip() for k, v in r.items() if k}
        if norm.get("category", "").lower() == "xss":
            out.append(norm)
    return out


def find_prefix_for_case(case_name, session):
    """Probe all known prefixes for THIS specific case. Cache result."""
    for prefix in XSS_PREFIXES:
        url = f"{BENCHMARK_BASE}/{prefix}/{case_name}"
        try:
            r = session.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                return prefix
        except Exception:
            continue
    return None


def field_names(case_name):
    return [case_name + s for s in FIELD_SUFFIXES] + ["answer"]


def send_all(session, url, case_name, payload):
    """Send payload through every channel and BOTH methods."""
    fields = field_names(case_name)
    params = {f: payload for f in fields}
    data = {f: payload for f in fields}
    cookies = {f: payload for f in fields}
    headers = {
        "Referer": payload,
        "User-Agent": payload,
        case_name: payload,
        case_name + "Area": payload,
        "X-Forwarded-For": payload,
        "X-Real-IP": payload,
        "Origin": payload,
    }

    results = []
    for method in ("post", "get"):
        try:
            r = getattr(session, method)(
                url,
                params=params,
                data=data if method == "post" else None,
                cookies=cookies,
                headers=headers,
                timeout=15,
                verify=False,
                allow_redirects=True,
            )
            results.append((method.upper(), r))
        except Exception:
            results.append((method.upper(), None))
    return results


def main():
    init_db()
    cases = load_xss_cases()
    print(f"[*] Capturing {len(cases)} XSS cases (per-case prefix detection)")

    session = requests.Session()
    # Warm up the session against the homepage (gets any session cookies)
    try:
        session.get(f"{BENCHMARK_BASE}/", verify=False, timeout=10)
    except Exception:
        pass

    prefix_cache = {}
    skipped = []

    for i, case in enumerate(cases, 1):
        case_name = case["# test name"]

        if case_name not in prefix_cache:
            prefix = find_prefix_for_case(case_name, session)
            prefix_cache[case_name] = prefix

        prefix = prefix_cache[case_name]
        if not prefix:
            skipped.append(case_name)
            if i <= 5 or i % 50 == 0:
                print(f"[{i}/{len(cases)}] {case_name}: SKIPPED (no working prefix)")
            continue

        url = f"{BENCHMARK_BASE}/{prefix}/{case_name}"
        token, payloads = make_probes()
        saved = 0

        for payload in payloads:
            for method, r in send_all(session, url, case_name, payload):
                if r is None:
                    continue
                try:
                    save_capture({
                        "case_name": case_name,
                        "prefix": prefix,
                        "target_url": url,
                        "param": case_name,
                        "payload": payload,
                        "token": token,
                        "method": method,
                        "status": r.status_code,
                        "headers": dict(r.headers),
                        "body": r.text,
                        "elapsed_ms": 0,
                    })
                    saved += 1
                finally:
                    r.close()

        if i % 25 == 0 or i <= 5 or i == len(cases):
            print(f"[{i}/{len(cases)}] {case_name} [{prefix}]: {saved} rows")

    print(f"\n[+] Done. {len(cases) - len(skipped)} cases captured, {len(skipped)} skipped.")
    if skipped:
        print(f"[!] Skipped: {skipped[:20]}")
    print(f"[+] Data in {DB_PATH}")


if __name__ == "__main__":
    main()