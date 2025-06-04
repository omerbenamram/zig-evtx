#!/usr/bin/env python3
"""Find the first record where Zig XML differs from Python."""
import subprocess
import os
import sys
import difflib
from itertools import zip_longest

sys.path.insert(0, os.path.dirname(__file__))
from Evtx.Evtx import Evtx

LOG_PATH = 'tests/data/security.evtx'


def python_xmls(path: str):
    """Yield XML for each record using the Python parser."""
    with Evtx(path) as log:
        for record in log.records():
            yield record.xml()


def zig_xmls(path: str):
    """Yield XML for each record using the Zig parser."""
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
        yield out[start:end+8]
        pos = end + 8


def main() -> None:
    py_iter = python_xmls(LOG_PATH)
    zig_iter = zig_xmls(LOG_PATH)

    for i, (py_xml, zig_xml) in enumerate(zip_longest(py_iter, zig_iter), start=1):
        if py_xml != zig_xml:
            if py_xml is None:
                print(f'Python ended early. Zig has extra record {i}.')
                return
            if zig_xml is None:
                print(f'Zig ended early. Python has extra record {i}.')
                return
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
            print(f'\nFirst mismatch at record {i}')
            return
    print('All records match! \u2705')


if __name__ == '__main__':
    main()
