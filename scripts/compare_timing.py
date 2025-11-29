#!/usr/bin/env python3
"""Parse and compare timing outputs from Zig and Rust binaries."""
import re
import sys
from pathlib import Path

def parse_time_output(filepath):
    """Parse /usr/bin/time -l output into a dict of metrics."""
    metrics = {}
    content = Path(filepath).read_text()

    # Parse real/user/sys time line: "1.00 real         0.00 user         0.00 sys"
    time_match = re.search(r'(\d+\.\d+)\s+real\s+(\d+\.\d+)\s+user\s+(\d+\.\d+)\s+sys', content)
    if time_match:
        metrics['real'] = float(time_match.group(1))
        metrics['user'] = float(time_match.group(2))
        metrics['sys'] = float(time_match.group(3))

    # Parse other metrics: "3162112  maximum resident set size"
    for line in content.split('\n'):
        match = re.match(r'^\s*(\d+)\s+(.+)$', line)
        if match:
            value = int(match.group(1))
            key = match.group(2).strip()
            metrics[key] = value

    return metrics

def main():
    if len(sys.argv) != 3:
        print("Usage: compare_timing.py <zig_time.txt> <rust_time.txt>")
        sys.exit(1)

    zig_file = sys.argv[1]
    rs_file = sys.argv[2]

    zig_metrics = parse_time_output(zig_file)
    rs_metrics = parse_time_output(rs_file)

    # Get all unique keys
    all_keys = sorted(set(zig_metrics.keys()) | set(rs_metrics.keys()))

    # Print comparison table
    print("--- time comparison ---")
    print(f"{'Metric':<50} {'Zig':<20} {'Rust':<20} {'Ratio':<10}")
    print("-" * 100)

    for key in all_keys:
        zig_val = zig_metrics.get(key, None)
        rs_val = rs_metrics.get(key, None)

        zig_str = f"{zig_val}" if zig_val is not None else "-"
        rs_str = f"{rs_val}" if rs_val is not None else "-"

        ratio_str = "-"
        if zig_val is not None and rs_val is not None and rs_val != 0:
            ratio = zig_val / rs_val
            ratio_str = f"{ratio:.3f}x"

        print(f"{key:<50} {zig_str:<20} {rs_str:<20} {ratio_str:<10}")

if __name__ == '__main__':
    main()

