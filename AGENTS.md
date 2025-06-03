# Codex Development Guide for zig-evtx

## Overview
This project ports the `python-evtx` parser to Zig while keeping the original
Python implementation for reference.  Both languages share tests and a large
collection of debug scripts.

## Repository Layout
- `src/` – Zig source files (`evtx.zig`, `bxml_parser.zig`, `template_processor.zig`, etc.)
- `Evtx/` – Original Python modules
- `tests/` – Pytest suite with sample `.evtx` files
- `debug_*.py` and `.zig` – Various debugging helpers (avoid creating duplicates)
- `.justfile` – Convenience tasks for linting and running tests

## Environment Setup
1. Activate the virtual environment:
   ```bash
   source .venv/bin/activate
   ```
2. Install Python dependencies using `uv`:
   ```bash
   uv add <package>
   ```
3. Use `uv run` to execute Python tools or the test suite.

## Running Tests
- **Python:** `uv run pytest tests/` (or `just test`)
- **Zig unit tests:** `zig test src/test_runner.zig`
- **Zig/Python comparison:** `zig run test_template_comparison.zig`

Run both suites when modifying related code.

## Building and Running
Build the `evtx_dump` CLI and inspect an example log:
```bash
zig build
./zig-out/bin/evtx_dump tests/data/security.evtx
```

## Development Tips
- Keep dedicated tests for each Zig node type to verify binary output matches the Python parser
- Rely on the existing Python debug scripts to investigate issues
- Follow the standardized token and error definitions in `tokens.zig`
- Avoid hard‑coded shortcuts; parse data directly from the binary and deinit allocated memory
- Consult `zig_014.md` for Zig 0.14 syntax changes if needed

