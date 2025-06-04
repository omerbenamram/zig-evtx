#!/usr/bin/env python3
"""Diff XML of all records between Python and Zig implementations."""
import subprocess
import os
import sys
import difflib
from itertools import zip_longest

sys.path.insert(0, os.path.dirname(__file__))
from Evtx.Evtx import Evtx

DEFAULT_LOG = 'tests/data/security.evtx'


def python_xmls(path: str):
    """Yield XML strings from the reference Python parser."""
    with Evtx(path) as log:
        for record in log.records():
            yield record.xml()


def zig_xmls(path: str):
    """Yield XML strings from the Zig parser output."""
    result = subprocess.run(['./zig-out/bin/evtx_dump', path], capture_output=True)
    out = result.stdout.decode('utf-8', errors='ignore')
    pos = 0
    while True:
        start = out.find('<Event', pos)
        if start == -1:
            break
        end = out.find('</Event>', start)
        if end == -1:
            break
        yield out[start:end + 8]
        pos = end + 8


def main() -> None:
    log_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG

    mismatches = []
    for i, (py_xml, zig_xml) in enumerate(zip_longest(python_xmls(log_path), zig_xmls(log_path)), start=1):
        if py_xml != zig_xml:
            mismatches.append(i)
            if py_xml is None:
                print(f'Python ended early. Zig has extra record {i}.')
                break
            if zig_xml is None:
                print(f'Zig ended early. Python has extra record {i}.')
                break
            with open(f'python_record_{i}.xml', 'w') as f:
                f.write(py_xml)
            with open(f'zig_record_{i}.xml', 'w') as f:
                f.write(zig_xml)
            diff = difflib.unified_diff(
                py_xml.splitlines(keepends=True),
                zig_xml.splitlines(keepends=True),
                fromfile=f'python_record_{i}.xml',
                tofile=f'zig_record_{i}.xml',
            )
            sys.stdout.writelines(diff)
            print()

    if not mismatches:
        print('All records match! \u2705')
    else:
        print(f'Found {len(mismatches)} mismatching record(s): {", ".join(map(str, mismatches))}')


if __name__ == '__main__':
    main()
