<h1 align="center">EVTX (Zig)</h1>
<div align="center">
  <p><strong>A high-performance Windows EVTX parser and CLI in Zig, with Python bindings</strong></p>
</div>

## Features

- **Cross-platform**: Builds on Linux, macOS, and Windows via Zig 0.14.1
- **Multiple outputs**: XML, JSON, and JSON Lines (jsonl)
- **Concurrent parsing**: Multi-threaded mode for throughput; single-threaded for stable order
- **Python bindings**: Lightweight module via `ziggy-pydust` for streaming results

## Quick start

Prerequisites:

- Zig 0.14.1
- Python available on PATH (used by the build to vendor pydust)

Build the CLI and Python extension:

```bash
make build OPT=ReleaseFast
```

Run on a sample file (see `samples/`):

```bash
# XML (single-threaded for stable order)
zig-out/bin/evtx_dump_zig -t 1 -o xml samples/system.evtx

# JSON (single object)
zig-out/bin/evtx_dump_zig -t 1 -o json samples/system.evtx

# JSON Lines (line per record)
zig-out/bin/evtx_dump_zig -o jsonl samples/system.evtx
```

Or use the convenience Make targets:

```bash
# Dump a file to XML/JSON/JSONL
make xml  FILE=samples/system.evtx
make json FILE=samples/system.evtx
make jsonl FILE=samples/system.evtx
```

## CLI usage

```text
Usage: evtx_dump_zig [-v|-vv|-vvv] [-o xml|json|jsonl] [-s N] [-n N] [-t NUM_THREADS] <file.evtx>

Options:
  -o <mode>       Output mode: xml | json | jsonl
  -v|-vv|-vvv     Verbosity
  -n N            Limit to first N records
  -s N            Skip first N records
  -t N            Number of threads (1 enforces stable order)
  --no-checks     Disable CRC/consistency checks
```

Notes:

- With `-t > 1`, records may be emitted out-of-order for maximum throughput.
- With `-t 1`, records are emitted in order.

## Python bindings

The build produces a Python extension module `evtxzig` using `ziggy-pydust`.

Example: dump a file to JSON Lines into another file

```python
from evtxzig import dump_file_to_file

dump_file_to_file(
    path="samples/system.evtx",
    out_path="out.jsonl",
    format="jsonl",  # or "xml" / "json"
    skip_first=0,
    max_records=0,
    validate_checksums=True,
    verbosity=0,
)
```

Streaming iterator (JSON Lines by default):

```python
from evtxzig import _lib as evtxzig

it = evtxzig.Iter(path="samples/system.evtx", format="jsonl")
for line in it:
    print(line)
```

## Development

- Format: `zig fmt src/**/*.zig`
- Run tests: `make test`
- Benchmark harness: `make bench-zbench`

Environment variables used by `Makefile`:

- `TARGET` (default `native`): e.g., `x86_64-linux`, `aarch64-macos`, `x86_64-windows`
- `OPT` (default `ReleaseFast`): `Debug` | `ReleaseSafe` | `ReleaseFast` | `ReleaseSmall`

Example cross-compilation:

```bash
make build TARGET=x86_64-windows OPT=ReleaseFast
ls zig-out/bin/evtx_dump_zig*
```

## Samples

Real-world `.evtx` examples are provided in `samples/` for local testing and validation.

## License

Dual-licensed under **Apache-2.0** or **MIT** at your option.

