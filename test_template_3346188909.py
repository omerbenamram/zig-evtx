#!/usr/bin/env python3
"""
Test specific template ID 3346188909 that was causing corruption
"""

import subprocess
import os

os.chdir("/Users/omerba/Workspace/python-evtx")

# First, activate virtual environment and run Python parser to get the correct template
print("=== PYTHON TEMPLATE 3346188909 ===")
cmd = (
    "source .venv/bin/activate.fish && "
    'python -c "import Evtx.Evtx as evtx; '
    "fh = evtx.Evtx('tests/data/security.evtx'); "
    "for chunk in fh.chunks(): "
    "    for template in chunk.templates().values(): "
    "        if template.template_id() == 3346188909: "
    "            print(f'Found template {template.template_id()}'); "
    "            print(f'Template XML length: {len(template.xml())}'); "
    "            print('Template XML:'); "
    "            print(template.xml()); "
    "            break"
    '"'
)
subprocess.run(cmd, shell=True)

# Build and run Zig parser
print("\n\n=== BUILDING ZIG ===")
result = subprocess.run(["zig", "build", "-Doptimize=Debug"], capture_output=True, text=True)
if result.returncode != 0:
    print(f"Build failed:\n{result.stderr}")
    exit(1)

# Run Zig parser and look for the specific template in the output
print("\n=== ZIG TEMPLATE OUTPUT ===")
result = subprocess.run(["./zig-out/bin/evtx_dump", "tests/data/security.evtx"], capture_output=True, text=True)

# Search for template 3346188909 in stderr
print("\nSearching for template 3346188909 in logs...")
for line in result.stderr.split("\n"):
    if "3346188909" in line:
        print(line)
    # Also look for the hex version
    elif "c772ca6d" in line.lower():
        print(line)

# Also search for any template parsing info
print("\n=== TEMPLATE PARSING INFO ===")
for line in result.stderr.split("\n"):
    if "Template" in line and ("XML" in line or "parsing" in line):
        print(line[:200])  # Truncate long lines
