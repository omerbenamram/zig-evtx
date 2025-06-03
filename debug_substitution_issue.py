#!/usr/bin/env python3
"""
Debug substitution parsing issue in Zig EVTX parser
"""

import subprocess
import sys
import os

os.chdir("/Users/omerba/Workspace/python-evtx")

# Build Zig parser with debug output
print("Building Zig parser...")
result = subprocess.run(["zig", "build", "-Doptimize=Debug"], capture_output=True, text=True)
if result.returncode != 0:
    print(f"Build failed:\n{result.stderr}")
    sys.exit(1)

# Run the parser and capture both stdout and stderr
print("\nRunning Zig parser to debug substitution parsing...")
result = subprocess.run(["./zig-out/bin/evtx_dump", "tests/data/security.evtx"], capture_output=True, text=True)

# Look for error messages related to substitution parsing
print("\n=== SEARCHING FOR SUBSTITUTION ERRORS ===")
lines = result.stderr.split("\n")
for line in lines:
    if "substitution" in line.lower() or "failed to parse" in line.lower():
        print(f"ERROR: {line}")

# Also check stdout for the failed message
if "Failed to parse substitutions" in result.stdout:
    print("\nFound 'Failed to parse substitutions' in output")

    # Count occurrences
    count = result.stdout.count("Failed to parse substitutions")
    print(f"Number of failed substitutions: {count}")

# Look for the specific error logs
print("\n=== STDERR OUTPUT (first 50 lines) ===")
stderr_lines = result.stderr.split("\n")[:50]
for line in stderr_lines:
    if line.strip():
        print(line)

print("\n=== CHECKING FOR POSITION-RELATED ERRORS ===")
for line in result.stderr.split("\n"):
    if "pos" in line.lower() and ("error" in line.lower() or "fail" in line.lower()):
        print(line)
