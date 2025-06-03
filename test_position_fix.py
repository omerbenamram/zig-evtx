#!/usr/bin/env python3
"""
Test script to verify the position tracking fix for template parsing
"""

import subprocess
import sys
import os
from pathlib import Path

# Ensure we're in the project directory
os.chdir("/Users/omerba/Workspace/python-evtx")

# First, rebuild the Zig parser with our changes
print("Building Zig parser...")
result = subprocess.run(["zig", "build"], capture_output=True, text=True)
if result.returncode != 0:
    print(f"Build failed:\n{result.stderr}")
    sys.exit(1)
print("Build successful!")

# Test parsing the problematic template (ID 3346188909 at chunk offset 550)
print("\nTesting template parsing...")

# Run the Zig parser on the security.evtx file
zig_result = subprocess.run(["./zig-out/bin/evtx_dump", "tests/data/security.evtx"], capture_output=True, text=True)

if zig_result.returncode != 0:
    print(f"Zig parser failed:\n{zig_result.stderr}")
    sys.exit(1)

# Check if we still get the corrupted output
corrupted_pattern = 'ROOT<Event EventData="" Event""[Conditional Substitution'
if corrupted_pattern in zig_result.stdout:
    print("❌ FAIL: Still getting corrupted output!")
    print("The position tracking fix didn't resolve the issue.")

    # Extract a sample of the output around the corrupted part
    lines = zig_result.stdout.split("\n")
    for i, line in enumerate(lines):
        if corrupted_pattern in line:
            print(f"\nCorrupted output found at line {i}:")
            # Show context
            start = max(0, i - 2)
            end = min(len(lines), i + 3)
            for j in range(start, end):
                prefix = ">>> " if j == i else "    "
                print(f"{prefix}{lines[j][:200]}...")
            break
else:
    print("✅ SUCCESS: No corrupted output pattern detected!")

    # Run Python parser for comparison
    print("\nRunning Python parser for comparison...")

    # Activate virtual environment and run Python parser
    activate_cmd = (
        ". .venv/bin/activate && python scripts/evtx_dump.py tests/data/security.evtx 2>/dev/null | head -n 1000"
    )
    python_result = subprocess.run(activate_cmd, shell=True, capture_output=True, text=True)

    # Count well-formed Event elements in both outputs
    zig_events = zig_result.stdout.count("<Event")
    zig_events_closed = zig_result.stdout.count("</Event>")

    python_events = python_result.stdout.count("<Event")
    python_events_closed = python_result.stdout.count("</Event>")

    print(f"\nZig parser: {zig_events} <Event> tags, {zig_events_closed} </Event> tags")
    print(f"Python parser: {python_events} <Event> tags, {python_events_closed} </Event> tags")

    if zig_events == zig_events_closed and zig_events > 0:
        print("\n✅ All Event elements are properly closed!")
    else:
        print("\n⚠️  Some Event elements may not be properly closed")

print("\n=== Position tracking fix test complete ===")
