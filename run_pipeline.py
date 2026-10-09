"""
run_pipeline.py -- XSS scanner full pipeline orchestrator.

Runs every stage in order with clear progress output:

  1. Generate lab matrix         (lab/generate_matrix.py)
  2. Start Flask lab server      (lab/app.py, background)
  3. Capture HTTP responses      (scanner/run_capture.py)
  4. Run browser oracle          (lab/run_oracle.py)
  5. Evaluate all rules          (eval/run_eval.py)
  6. Compute statistics          (eval/stats.py)
  7. Stop Flask server

Optional (--with-benchmark):
  8. Capture benchmark responses (scanner/run_capture_benchmark.py)
  9. Evaluate on benchmark       (eval/run_eval_benchmark.py)

Usage:
  python run_pipeline.py
  python run_pipeline.py --with-benchmark
  python run_pipeline.py --skip-capture        # reuse existing captures.db
"""

import argparse
import os
import signal
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000


# ---------- Helpers ----------

def is_port_open(host, port, timeout=1.0):
    """Return True if something is listening on host:port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def banner(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def run(cmd, cwd=ROOT, check=True):
    """Run a shell command, stream output, return exit code."""
    print(f"$ {cmd}")
    result = subprocess.run(cmd, cwd=cwd, shell=True)
    if check and result.returncode != 0:
        print(f"[!] Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)
    return result.returncode


def stage(name, cmd):
    banner(name)
    t0 = time.time()
    run(cmd)
    print(f"[+] {name} done in {time.time() - t0:.1f}s")


# ---------- Flask server management ----------

def start_flask():
    """Start lab/app.py as a background process, return Popen object."""
    if is_port_open(FLASK_HOST, FLASK_PORT):
        print(f"[*] Flask already running on {FLASK_HOST}:{FLASK_PORT}")
        return None

    print(f"[*] Starting Flask on {FLASK_HOST}:{FLASK_PORT} ...")
    # Suppress Flask's own output unless it fails
    log = open("flask.log", "w")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "lab", "app.py")],
        cwd=ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
    )

    # Wait up to 15s for the server to come up
    for i in range(30):
        if is_port_open(FLASK_HOST, FLASK_PORT):
            print(f"[+] Flask ready after {i * 0.5:.1f}s")
            return proc
        time.sleep(0.5)

    print("[!] Flask did not start within 15s. Check flask.log for details.")
    proc.terminate()
    sys.exit(1)


def stop_flask(proc):
    if proc is None:
        return
    print("[*] Stopping Flask ...")
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


# ---------- Main pipeline ----------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--with-benchmark", action="store_true",
                        help="Also run the OWASP Benchmark pipeline")
    parser.add_argument("--skip-capture", action="store_true",
                        help="Skip capture (reuse existing captures.db)")
    parser.add_argument("--skip-oracle", action="store_true",
                        help="Skip browser oracle (reuse existing manifest.csv)")
    args = parser.parse_args()

    t_start = time.time()

    # ---- Lab pipeline ----
    stage("Stage 1 / 6: Generate lab matrix",
          f'"{sys.executable}" lab/generate_matrix.py')

    flask_proc = start_flask()
    try:
        if not args.skip_capture:
            stage("Stage 2 / 6: Capture HTTP responses",
                  f'"{sys.executable}" scanner/run_capture.py')
        else:
            print("[*] Skipping capture (--skip-capture)")

        if not args.skip_oracle:
            stage("Stage 3 / 6: Run browser oracle (ground truth)",
                  f'"{sys.executable}" lab/run_oracle.py')
        else:
            print("[*] Skipping oracle (--skip-oracle)")

        stage("Stage 4 / 6: Evaluate all rules (A0, A1, B, C)",
              f'"{sys.executable}" eval/run_eval.py')

        stage("Stage 5 / 6: Compute statistics and confidence intervals",
              f'"{sys.executable}" eval/stats.py')

        stage("Stage 6 / 6: Print results summary",
              f'"{sys.executable}" -c "print(\'Pipeline complete. See output above.\')"')
    finally:
        stop_flask(flask_proc)

    # ---- Optional Benchmark pipeline ----
    if args.with_benchmark:
        stage("Benchmark 1 / 2: Capture OWASP Benchmark responses",
              f'"{sys.executable}" scanner/run_capture_benchmark.py')
        stage("Benchmark 2 / 2: Evaluate on OWASP Benchmark",
              f'"{sys.executable}" eval/run_eval_benchmark.py')

    banner(f"PIPELINE COMPLETE in {time.time() - t_start:.1f}s")
    print("Results above. Logs in flask.log if needed.")


if __name__ == "__main__":
    main()