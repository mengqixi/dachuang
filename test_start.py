"""Manual local startup smoke check.

This file intentionally exposes no pytest test. Run it explicitly when a
temporary local service check is needed: ``python test_start.py``.
"""

from pathlib import Path
import subprocess
import sys
import time

import requests


def main() -> int:
    project_dir = Path(__file__).resolve().parent
    proc = subprocess.Popen(
        [sys.executable, "run_server_simple.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(project_dir),
    )
    try:
        time.sleep(3)
        response = requests.get("http://localhost:8080/api/get_stats", timeout=5)
        print("API Response: %s" % response.status_code)
        print("Response Content: %s..." % response.text[:500])
        return 0 if response.ok else 1
    except Exception as exc:
        print("Startup check failed: %s" % exc)
        return 1
    finally:
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=5)
        if stdout:
            print(stdout.decode("utf-8", errors="ignore"))
        if stderr:
            print(stderr.decode("utf-8", errors="ignore"), file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
