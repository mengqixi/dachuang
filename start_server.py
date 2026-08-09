#!/usr/bin/env python3
"""Cross-platform launcher for the canonical application entry point."""

from pathlib import Path
import subprocess
import sys


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent
    raise SystemExit(subprocess.call([sys.executable, "app.py"], cwd=project_root))
