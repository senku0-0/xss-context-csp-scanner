import csv
import time
import requests
import os
import sys

# Add the parent directory to the path so we can import scanner modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.inject import make_probes
from scanner.capture import init_db, save_capture

# Silence SSL warnings
requests.packages.urllib3.disable_warnings()

def run_capture():
    # Initialize the DB table (this will do nothing if it already exists)
    init_db()
    
    # Read the lab matrix
    matrix_path = os.path.join(os.path.dirname(__file__), "..", "lab", "matrix.csv")
    with open(matrix_path, newline="", encoding="utf-8") as f:
        cases = list(csv.DictReader(f))

    print(f"[*] Starting capture on {len(cases)} lab cases...")
    
    for i, case in enumerate(cases, 1):
        target_url = f"http://127.0.0.1:5000/page/{case['id']}"
        
        # Print progress
        print(f"[{i}/{len(cases)}] Capturing {case['id']}...")
        
        token, payloads = make_probes()
        
        for payload in payloads:
            start_time = time.perf_counter()
            try:
                r = requests.get(target_url, params={"q": payload}, timeout=5, stream=True)
                elapsed = (time.perf_counter() - start_time) * 1000
                
                # Call the new save_capture (no 'con' argument)
                save_capture({
                    "target_url": target_url,
                    "method": "GET",
                    "param": "q",
                    "payload": payload,
                    "token": token,
                    "status": r.status_code,
                    "headers": dict(r.headers),
                    "body": r.text,
                    "elapsed_ms": elapsed
                })
                r.close()
            except Exception as e:
                print(f"[!] Error on {target_url}: {e}")

    print(f"[+] Capture complete! Data saved to captures.db")

if __name__ == "__main__":
    run_capture()