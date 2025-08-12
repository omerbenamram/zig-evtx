#!/usr/bin/env python3
import argparse
import sys

from evtxzig import _lib


def parse_args(argv):
    p = argparse.ArgumentParser(prog="evtx_dump_py")
    p.add_argument("file", help="Path to .evtx file")
    p.add_argument("-o", dest="format", choices=["xml", "json", "jsonl"], default="xml")
    p.add_argument("-v", action="count", default=0)
    p.add_argument("-n", dest="max_records", type=int, default=0)
    p.add_argument("-s", dest="skip_first", type=int, default=0)
    p.add_argument("--no-checks", dest="no_checks", action="store_true")
    return p.parse_args(argv)


def stream_with_iter(ns):
    fmt_for_iter = "jsonl" if ns.format == "json" else ns.format
    it = _lib.Iter(
        ns.file,
        fmt_for_iter,
        skip_first=ns.skip_first,
        max_records=ns.max_records,
        validate_checksums=(not ns.no_checks),
        verbosity=int(min(ns.v, 255)),
    )

    def coerce_line_to_text(val: object) -> str:
        # pydust may wrap the underlying Python string inside a small dict-like form
        try:
            if isinstance(val, dict) and "py" in val:
                inner = val["py"]
                if isinstance(inner, (str, bytes, bytearray)):
                    return (
                        inner
                        if isinstance(inner, str)
                        else inner.decode("utf-8", errors="strict")
                    )
        except Exception:
            pass
        if isinstance(val, str):
            return val
        if isinstance(val, (bytes, bytearray)):
            return val.decode("utf-8", errors="strict")
        return str(val)

    if ns.format == "json":
        # Assemble a JSON array from per-record JSON objects
        write = sys.stdout.write
        first = True
        write("[\n")
        for line in it:
            obj = coerce_line_to_text(line).rstrip("\n")
            if first:
                write(obj)
                first = False
            else:
                write(",\n")
                write(obj)
        write("\n]\n")
    else:
        # xml and jsonl already contain trailing newlines per record
        write = sys.stdout.write
        for line in it:
            write(coerce_line_to_text(line))


def main(argv):
    ns = parse_args(argv)
    try:
        stream_with_iter(ns)
    except BrokenPipeError:
        try:
            sys.stdout.flush()
        except Exception:
            pass
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
