#!/usr/bin/env python3
import sys
from pathlib import Path

PROJECT_ROOT = "/Users/omerba/Workspace/gpt5-codex-zig-evtx"
sys.path.insert(0, PROJECT_ROOT)

from evtxzig import _lib


def main():
    sample = Path(PROJECT_ROOT) / "samples" / "system.evtx"
    # Stream records on-the-fly via iterator (no full buffering)
    it = _lib.Iter(
        str(sample),
        "jsonl",
        skip_first=0,
        validate_checksums=True,
        verbosity=0,
    )
    for i, line in enumerate(it, 1):
        print(line)


if __name__ == "__main__":
    main()
