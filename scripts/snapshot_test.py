#!/usr/bin/env python3
"""Snapshot-based regression tests for EVTX parser.

Compares parser output against saved expected snapshots.
Similar to cargo insta - stores expected output as files.

Usage:
    snapshot_test.py                     # Run all tests
    snapshot_test.py --update            # Update snapshots from current output
    snapshot_test.py --test <name>       # Run specific test
"""

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Add scripts dir to path for normalize_xml
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))
from normalize_xml import normalize_xml

PROJECT_ROOT = SCRIPT_DIR.parent
SNAPSHOTS_DIR = PROJECT_ROOT / "tests" / "snapshots"
ZIG_BINARY = PROJECT_ROOT / "zig-out" / "bin" / "evtx_dump_zig"
SAMPLES_DIR = PROJECT_ROOT / "samples"


@dataclass
class SnapshotTest:
    """A snapshot test case."""

    name: str
    description: str
    evtx_file: str
    record_id: int  # EventRecordID to extract
    expected_file: str

    def expected_path(self) -> Path:
        return SNAPSHOTS_DIR / self.expected_file

    def actual_path(self) -> Path:
        return SNAPSHOTS_DIR / self.expected_file.replace(".expected.", ".actual.")


# Define regression tests
TESTS = [
    SnapshotTest(
        name="trailing_spaces",
        description="String values should have trailing spaces trimmed (e.g., 'Advapi  ' -> 'Advapi')",
        evtx_file="security.evtx",
        record_id=16,
        expected_file="record_16_trailing_spaces.expected.xml",
    ),
    SnapshotTest(
        name="nested_binxml",
        description="Nested BinXML (type 0x21) should render child elements (e.g., UserData/ServiceShutdown)",
        evtx_file="security.evtx",
        record_id=38,
        expected_file="record_38_nested_binxml.expected.xml",
    ),
]


def get_record_by_id(evtx_path: Path, record_id: int) -> str:
    """Extract a single record by EventRecordID using the Zig parser."""
    # Use the parser to output all records, then filter
    result = subprocess.run(
        [str(ZIG_BINARY), "-o", "xml", "-t", "1", str(evtx_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Parser failed: {result.stderr}")

    # Parse output to find the specific record
    lines = result.stdout.split("\n")
    in_record = False
    record_lines = []
    current_rid = None

    for line in lines:
        if "<Event " in line or (line.strip() == "<Event>" and not in_record):
            in_record = True
            record_lines = [line]
        elif in_record:
            record_lines.append(line)
            if "<EventRecordID>" in line:
                # Extract the ID
                import re

                match = re.search(r"<EventRecordID>(\d+)</EventRecordID>", line)
                if match:
                    current_rid = int(match.group(1))
            if "</Event>" in line:
                in_record = False
                if current_rid == record_id:
                    return "\n".join(record_lines)
                record_lines = []
                current_rid = None

    raise ValueError(f"Record with EventRecordID={record_id} not found")


def run_test(test: SnapshotTest, update: bool = False) -> bool:
    """Run a single snapshot test. Returns True if passed."""
    evtx_path = SAMPLES_DIR / test.evtx_file

    if not evtx_path.exists():
        print(f"  SKIP: {test.evtx_file} not found")
        return True

    if not ZIG_BINARY.exists():
        print(f"  SKIP: Zig binary not built")
        return True

    try:
        # Get actual output
        actual = get_record_by_id(evtx_path, test.record_id)
        actual_normalized = normalize_xml(actual)

        if update:
            # Update the expected file
            test.expected_path().write_text(actual)
            print(f"  UPDATED: {test.expected_file}")
            return True

        # Load and normalize expected
        if not test.expected_path().exists():
            print(f"  FAIL: Expected file not found: {test.expected_file}")
            print(f"        Run with --update to create it")
            return False

        expected = test.expected_path().read_text()
        expected_normalized = normalize_xml(expected)

        if actual_normalized == expected_normalized:
            print(f"  PASS")
            return True
        else:
            # Save actual for debugging
            test.actual_path().write_text(actual)
            print(f"  FAIL: Output differs from expected")
            print(f"        Expected: {test.expected_path()}")
            print(f"        Actual:   {test.actual_path()}")

            # Show first difference
            exp_lines = expected_normalized.split("\n")
            act_lines = actual_normalized.split("\n")
            for i, (e, a) in enumerate(zip(exp_lines, act_lines)):
                if e != a:
                    print(f"        First diff at line {i + 1}:")
                    print(f"          Expected: {e[:80]}")
                    print(f"          Actual:   {a[:80]}")
                    break
            return False

    except Exception as e:
        print(f"  ERROR: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Snapshot regression tests")
    parser.add_argument(
        "--update",
        "-u",
        action="store_true",
        help="Update expected snapshots from current output",
    )
    parser.add_argument("--test", "-t", type=str, help="Run only the specified test")
    args = parser.parse_args()

    # Ensure snapshots directory exists
    SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)

    tests_to_run = TESTS
    if args.test:
        tests_to_run = [t for t in TESTS if t.name == args.test]
        if not tests_to_run:
            print(f"Unknown test: {args.test}")
            print(f"Available tests: {', '.join(t.name for t in TESTS)}")
            sys.exit(1)

    print("Running snapshot tests...")
    print()

    passed = 0
    failed = 0

    for test in tests_to_run:
        print(f"[{test.name}] {test.description}")
        if run_test(test, update=args.update):
            passed += 1
        else:
            failed += 1
        print()

    print(f"Results: {passed} passed, {failed} failed")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
