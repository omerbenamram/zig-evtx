#!/usr/bin/env python3
"""
Test just the first record to debug substitution parsing
"""

import subprocess
import os

os.chdir("/Users/omerba/Workspace/python-evtx")

# Build and run Zig parser for just one record
print("Building Zig parser...")
subprocess.run(["zig", "build", "-Doptimize=Debug"], check=True)

# Run and capture just the first few records
print("\nRunning Zig parser for first record...")
result = subprocess.run(["./zig-out/bin/evtx_dump", "tests/data/security.evtx"], capture_output=True, text=True)

# Look for the first Event element
stdout_lines = result.stdout.split("\n")
for i, line in enumerate(stdout_lines):
    if "<Event" in line or "Failed to parse" in line:
        print(f"Line {i}: {line}")
        if i < len(stdout_lines) - 1 and ("Failed" in line or "Event" in line):
            # Show context
            for j in range(max(0, i - 2), min(len(stdout_lines), i + 3)):
                print(f"  {j}: {stdout_lines[j]}")
        break

# Check errors related to first record
print("\n=== ERRORS RELATED TO FIRST RECORD ===")
stderr_lines = result.stderr.split("\n")
in_first_record = False
line_count = 0

for line in stderr_lines:
    if "record_num=1" in line or "Record 1" in line:
        in_first_record = True
    elif "record_num=2" in line or "Record 2" in line:
        break  # Stop at second record

    if in_first_record and line.strip():
        print(line)
        line_count += 1
        if line_count > 100:
            print("... (truncated)")
            break
    elif "parseTemplate" in line and "3346188909" in line:
        print(f"Template parsing: {line}")
    elif "Failed to parse substitution" in line:
        print(f"ERROR: {line}")
