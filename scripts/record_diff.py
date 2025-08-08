#!/usr/bin/env python3
import argparse
import difflib
import os
import re
import sys


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def write_text(path: str, data: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)


def normalize_xml(xml: str) -> str:
    # Remove XML prolog and Rust's "Record N" lines
    lines = []
    for line in xml.splitlines():
        if line.startswith("<?xml ") or re.match(r"^Record\s+\d+$", line):
            continue
        lines.append(line)
    xml2 = "\n".join(lines)
    # Expand self-closing tags: <Tag .../> -> <Tag ...></Tag>
    # Keep this conservative to avoid touching comments/CDATA
    xml3 = re.sub(r"<([A-Za-z0-9:_-]+)([^>]*)/>", r"<\1\2></\1>", xml2)
    return xml3


def split_events(xml: str) -> list[str]:
    # Match minimal Event blocks
    pattern = re.compile(r"<Event(?:\s[^>]*)?>.*?</Event>", re.S)
    return [m.group(0) for m in pattern.finditer(xml)]


def find_index_by_rid(events: list[str], rid: str) -> int | None:
    # Return 1-based index to match awk NR semantics
    tag = f"<EventRecordID>{rid}</EventRecordID>"
    for i, ev in enumerate(events, start=1):
        if tag in ev:
            return i
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rs", required=True, help="Path to Rust XML (raw)")
    ap.add_argument("--zig", required=True, help="Path to Zig XML (raw)")
    ap.add_argument("--rid", help="EventRecordID to select")
    ap.add_argument("--index", help="1-based ordinal to select")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--name", required=True)
    args = ap.parse_args()

    out_dir = args.out_dir
    name = args.name
    os.makedirs(out_dir, exist_ok=True)

    # Prefer normalized full files if present to avoid re-normalizing entire inputs repeatedly
    rs_norm_path = os.path.join(out_dir, f"{name}.rs.norm.xml")
    zig_norm_path = os.path.join(out_dir, f"{name}.zig.norm.xml")
    if os.path.exists(rs_norm_path) and os.path.exists(zig_norm_path):
        rs_xml = read_text(rs_norm_path)
        zig_xml = read_text(zig_norm_path)
    else:
        rs_xml = normalize_xml(read_text(args.rs))
        zig_xml = normalize_xml(read_text(args.zig))

    rs_events = split_events(rs_xml)
    zig_events = split_events(zig_xml)
    if not rs_events:
        print("No <Event> blocks found in Rust XML", file=sys.stderr)
        sys.exit(2)
    if not zig_events:
        print("No <Event> blocks found in Zig XML", file=sys.stderr)
        sys.exit(2)

    if args.rid:
        idx = find_index_by_rid(rs_events, args.rid)
        if idx is None:
            print(f"RID {args.rid} not found in Rust XML", file=sys.stderr)
            sys.exit(3)
    else:
        try:
            idx = int(args.index)
        except Exception:
            print("Provide --rid or --index", file=sys.stderr)
            sys.exit(4)

    # Clamp index into range
    if idx < 1 or idx > len(rs_events):
        print(
            f"Index {idx} out of range for Rust events (len={len(rs_events)})",
            file=sys.stderr,
        )
        sys.exit(5)
    if idx > len(zig_events):
        print(
            f"Index {idx} out of range for Zig events (len={len(zig_events)})",
            file=sys.stderr,
        )
        sys.exit(6)

    rs_one = rs_events[idx - 1]
    zig_one = zig_events[idx - 1]

    rs_one_norm_path = os.path.join(out_dir, f"{name}.rs.one.norm.xml")
    zig_one_norm_path = os.path.join(out_dir, f"{name}.zig.one.norm.xml")
    write_text(rs_one_norm_path, rs_one)
    write_text(zig_one_norm_path, zig_one)

    # Print unified diff to stdout
    diff = difflib.unified_diff(
        rs_one.splitlines(True),
        zig_one.splitlines(True),
        fromfile=rs_one_norm_path,
        tofile=zig_one_norm_path,
        n=3,
    )
    sys.stdout.writelines(diff)
    print(f"Wrote: {rs_one_norm_path} and {zig_one_norm_path}")


if __name__ == "__main__":
    main()
