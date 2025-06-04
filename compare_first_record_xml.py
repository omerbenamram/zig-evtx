#!/usr/bin/env python3
"""Compare first record XML between Python and Zig parsers."""
import subprocess
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from Evtx.Evtx import Evtx

LOG_PATH = 'tests/data/security.evtx'


def python_xml(path: str) -> str:
    with Evtx(path) as log:
        record = next(log.records())
        xml = record.xml()
        print(f"Python XML length: {len(xml)}")
        return xml


def zig_xml(path: str) -> str:
    result = subprocess.run(['./zig-out/bin/evtx_dump', path], capture_output=True)
    out = result.stdout.decode('utf-8', errors='ignore')
    start = out.find('<Event')
    end = out.find('</Event>', start)
    if start != -1 and end != -1:
        xml = out[start:end+8]
    else:
        xml = ''
    print(f"Zig XML length: {len(xml)}")
    return xml


def main() -> None:
    py = python_xml(LOG_PATH)
    zig = zig_xml(LOG_PATH)
    with open('python_first.xml', 'w') as f:
        f.write(py)
    with open('zig_first.xml', 'w') as f:
        f.write(zig)
    if py == zig:
        print('XML outputs match! \u2705')
    else:
        print('XML outputs differ.')


if __name__ == '__main__':
    main()
