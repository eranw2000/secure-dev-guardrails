#!/usr/bin/env python3
"""Run every detection regression test in this directory.

    python3 ci/tests/run_detection_tests.py

Files are found by name (`test_*_detections.py`), so a new rule's test is picked up by CI and
pre-commit the moment it is added, with nothing else to edit. An empty match fails the run,
so a renamed directory or a broken glob cannot pass as a clean result.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    tests = sorted(HERE.glob("test_*_detections.py"))
    if not tests:
        print(f"FAIL: no test_*_detections.py files found in {HERE}")
        return 1
    failed = []
    for test in tests:
        print(f"== {test.name}", flush=True)
        if subprocess.run([sys.executable, str(test)]).returncode != 0:
            failed.append(test.name)
    print()
    if failed:
        print(f"FAIL: {len(failed)} of {len(tests)} detection test files failed: {failed}")
        return 1
    print(f"PASS: all {len(tests)} detection test files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
