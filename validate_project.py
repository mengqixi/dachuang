#!/usr/bin/env python3
"""Read-only structural and syntax validation for the active application."""

from pathlib import Path
import py_compile
import sys


PROJECT_ROOT = Path(__file__).resolve().parent
REQUIRED_FILES = (
    "app.py",
    "index.html",
    "requirements.txt",
    "config/config.yaml",
    "src/preprocess/feature_engineering.py",
    "src/preprocess/federated_splitter.py",
    "src/detection/ensemble_detector.py",
    "src/detection/scoring.py",
    "src/federated/aggregator.py",
    "src/federated/client.py",
    "src/user_submission_manager.py",
    "src/utils/atomic_files.py",
    "tests/test_data_model_consistency.py",
    "tests/test_http_surface.py",
)


def main() -> int:
    errors = []
    print("=== 项目结构 ===")
    for relative in REQUIRED_FILES:
        path = PROJECT_ROOT / relative
        exists = path.is_file()
        print(f"[{'OK' if exists else 'MISSING'}] {relative}")
        if not exists:
            errors.append(f"缺少文件: {relative}")

    print("\n=== Python 语法 ===")
    python_files = [PROJECT_ROOT / "app.py"]
    python_files.extend((PROJECT_ROOT / "src").rglob("*.py"))
    python_files.extend((PROJECT_ROOT / "tests").rglob("*.py"))
    for path in sorted(python_files):
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as error:
            relative = path.relative_to(PROJECT_ROOT)
            errors.append(f"语法错误: {relative}: {error.msg}")

    if errors:
        for error in errors:
            print(f"[FAIL] {error}")
        return 1
    print(f"[OK] 已检查 {len(python_files)} 个 Python 文件")
    print("\n下一步: python -m unittest discover tests -v")
    return 0


if __name__ == "__main__":
    sys.exit(main())
