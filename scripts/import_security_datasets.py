"""Import local security datasets into the unified training schema.

Examples:
  python scripts/import_security_datasets.py --dataset local_generated_train
  python scripts/import_security_datasets.py --dataset unsw_nb15 --per-class-limit 20000
"""

import argparse
import json
import os
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.datasets.security_dataset_importer import SecurityDatasetImporter  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Import security datasets into a unified CSV schema.")
    parser.add_argument("--dataset", required=True, help="Dataset source id from config/dataset_sources.json")
    parser.add_argument("--config", default="config/dataset_sources.json", help="Dataset source config path")
    parser.add_argument("--output", default=None, help="Output CSV path")
    parser.add_argument("--metadata", default=None, help="Output metadata JSON path")
    parser.add_argument("--per-class-limit", type=int, default=None, help="Maximum rows per attack type")
    args = parser.parse_args()

    importer = SecurityDatasetImporter(args.config)
    metadata = importer.import_source(
        source_id=args.dataset,
        output_path=args.output,
        metadata_path=args.metadata,
        per_class_limit=args.per_class_limit,
    )
    print(json.dumps({
        "dataset": metadata["source_id"],
        "sampled_rows": metadata["sampled_rows"],
        "raw_rows": metadata["raw_rows"],
        "output_path": metadata["output_path"],
        "trainable": metadata["trainable"],
        "attack_type_distribution": metadata["attack_type_distribution"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
