#!/usr/bin/env python3
import sys
from pathlib import Path

PROJECT_ROOT = "/Users/omerba/Workspace/gpt5-codex-zig-evtx"
sys.path.insert(0, PROJECT_ROOT)

from evtxzig import _lib


def main():
    sample = Path(PROJECT_ROOT) / "samples" / "system.evtx"
    it = _lib.Iter(
        str(sample), "jsonl", max_records=10, validate_checksums=True, verbosity=0
    )
    for line in it:
        print(line)


if __name__ == "__main__":
    main()
