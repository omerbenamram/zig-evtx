#!/usr/bin/env python3
"""Show a unified diff of the first record XML from Python and Zig parsers."""
import subprocess
import os
import sys
from pathlib import Path
import difflib
from textwrap import shorten
from lxml import etree

# Use the project root as module path for Evtx
sys.path.insert(0, os.path.dirname(__file__))
from Evtx.Evtx import Evtx

LOG_PATH = Path('tests/data/security.evtx')
MAX_LINE_LEN = 200


def pretty_xml(xml: str) -> str:
    """Pretty print XML using lxml to make line-based diffs stable."""
    if not xml.strip():
        return ""
    try:
        root = etree.fromstring(xml.encode('utf-8'))
    except etree.XMLSyntaxError:
        return xml.strip()
    return etree.tostring(root, encoding='unicode', pretty_print=True)


def python_xml(path: Path) -> str:
    with Evtx(str(path)) as log:
        record = next(log.records())
        return record.xml()


def zig_xml(path: Path) -> str:
    result = subprocess.run(['./zig-out/bin/evtx_dump', str(path)], capture_output=True)
    out = result.stdout.decode('utf-8', errors='ignore')
    start = out.find('<Event')
    end = out.find('</Event>', start)
    if start != -1 and end != -1:
        return out[start:end + 8]
    return ''


def truncate(line: str) -> str:
    """Ensure a single line does not exceed MAX_LINE_LEN characters."""
    return shorten(line, width=MAX_LINE_LEN, placeholder='…')


def main() -> None:
    py_raw = python_xml(LOG_PATH)
    zig_raw = zig_xml(LOG_PATH)

    py_pretty = pretty_xml(py_raw)
    if not zig_raw:
        print("Warning: zig parser produced no XML", file=sys.stderr)
        zig_pretty = ""
    else:
        zig_pretty = pretty_xml(zig_raw)

    Path('python_first.xml').write_text(py_pretty)
    Path('zig_first.xml').write_text(zig_pretty)

    py_lines = py_pretty.splitlines()
    zig_lines = zig_pretty.splitlines()
    diff = difflib.unified_diff(py_lines, zig_lines, fromfile='python_first.xml', tofile='zig_first.xml', lineterm='', n=3)

    print('\n'.join(truncate(l) for l in diff))


if __name__ == '__main__':
    main()
