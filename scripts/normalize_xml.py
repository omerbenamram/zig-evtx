#!/usr/bin/env python3
"""Normalize EVTX XML output for comparison between Rust and Zig parsers.

Handles cosmetic differences that don't affect semantic content:
- GUID formatting: braces and case
- Empty attributes (Qualifiers, ActivityID, etc.)
- Hex value case
- Whitespace in empty elements
- Blank lines between events
"""

import re
import sys
from pathlib import Path


def normalize_xml(content: str) -> str:
    """Normalize XML content for comparison."""
    s = content

    # Remove XML prolog
    s = re.sub(r"<\?xml[^?]*\?>\s*", "", s)

    # Remove empty Qualifiers attribute
    s = re.sub(r' Qualifiers=""', "", s)

    # Remove empty correlation/security attributes
    s = re.sub(r' ActivityID=""', "", s)
    s = re.sub(r' RelatedActivityID=""', "", s)
    s = re.sub(r' UserID=""', "", s)

    # Normalize GUID in attributes: remove braces and uppercase
    # Matches Guid="..." with optional braces
    s = re.sub(
        r'Guid="\{?([^}"]+)\}?"', lambda m: 'Guid="' + m.group(1).upper() + '"', s
    )

    # Normalize GUID in element content (e.g., LogonGuid values)
    # Matches >GUID< patterns with optional braces
    s = re.sub(
        r">\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?<",
        lambda m: ">" + m.group(1).upper() + "<",
        s,
    )

    # Normalize hex values to uppercase (0x3e7 -> 0x3E7)
    s = re.sub(
        r"0x([0-9a-fA-F]+)", lambda m: "0x" + m.group(1).upper(), s, flags=re.IGNORECASE
    )

    # Remove consecutive blank lines
    s = re.sub(r"\n\n+", "\n", s)

    # Collapse empty elements with internal whitespace
    # <Tag attr="x">\n    </Tag> -> <Tag attr="x"></Tag>
    s = re.sub(r"<([A-Za-z0-9:_-]+)([^>]*)>\s*</\1>", r"<\1\2></\1>", s)

    # Strip leading/trailing whitespace
    s = s.strip()

    return s


def main():
    if len(sys.argv) < 2:
        print("Usage: normalize_xml.py <file> [--in-place]", file=sys.stderr)
        print("       normalize_xml.py --stdin", file=sys.stderr)
        sys.exit(1)

    in_place = "--in-place" in sys.argv or "-i" in sys.argv

    if sys.argv[1] == "--stdin":
        content = sys.stdin.read()
        print(normalize_xml(content), end="")
    else:
        path = Path(sys.argv[1])
        content = path.read_text()
        normalized = normalize_xml(content)

        if in_place:
            path.write_text(normalized)
        else:
            print(normalized, end="")


if __name__ == "__main__":
    main()
