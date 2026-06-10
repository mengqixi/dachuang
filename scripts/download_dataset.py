#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Download a small, usable network-security dataset for this project.

The script downloads UNSW-NB15 CSV files into data/datasets/UNSW-NB15.  It
limits rows by default so the Flask app can train and detect quickly on a
small server.  If the download fails, it creates the project's generated CSV
dataset instead so the data pipeline still has real local CSV files to use.
"""

import argparse
import csv
import os
import sys
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UNSW_DIR = ROOT / "data" / "datasets" / "UNSW-NB15"
GENERATED_DIR = ROOT / "data" / "generated"

URLS = {
    "UNSW_NB15_training-set.csv": "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_training-set.csv",
    "UNSW_NB15_testing-set.csv": "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv",
}


def copy_limited_csv(src, dest: Path, limit: int) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    text = (line.decode("utf-8", errors="replace") for line in src)
    rows = list(csv.reader(text))
    if not rows:
        return 0

    header, data = rows[0], rows[1:]
    if limit and len(data) > limit:
        if limit == 1:
            selected = [data[0]]
        else:
            step = (len(data) - 1) / float(limit - 1)
            selected = [data[int(round(i * step))] for i in range(limit)]
    else:
        selected = data

    with dest.open("w", encoding="utf-8", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(header)
        writer.writerows(selected)
    return len(selected)


def download_unsw(limit: int) -> bool:
    per_file = max(1, limit // len(URLS))
    ok = True
    for filename, url in URLS.items():
        dest = UNSW_DIR / filename
        print(f"Downloading {filename} -> {dest}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "dachuang-dataset-downloader/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                rows = copy_limited_csv(resp, dest, per_file)
            print(f"Saved {rows} rows: {dest}")
        except Exception as exc:
            ok = False
            print(f"Download failed for {filename}: {exc}", file=sys.stderr)
    return ok


def ensure_generated_fallback() -> None:
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    train = GENERATED_DIR / "train.csv"
    test = GENERATED_DIR / "test.csv"
    if train.exists() and test.exists():
        print(f"Fallback dataset already exists: {train}, {test}")
        return
    sys.path.insert(0, str(ROOT))
    from src.data_generator import ensure_data_generated

    ensure_data_generated()
    print(f"Generated fallback dataset: {train}, {test}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="unsw-nb15", choices=["unsw-nb15"])
    parser.add_argument("--limit", type=int, default=50000, help="maximum rows across downloaded files")
    args = parser.parse_args()

    ok = download_unsw(args.limit)
    if not ok:
        ensure_generated_fallback()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
