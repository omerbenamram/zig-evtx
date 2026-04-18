# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Zig implementation of a Windows Event Log (EVTX) parser that reads EVTX files and outputs them in XML, JSON, or JSONL format. The project aims for parity with the Rust `evtx_dump` tool.

## Build Commands

```bash
# Build the project
zig build -Doptimize=ReleaseFast

# Run with a sample file
zig build run -- -o xml samples/system.evtx

# Run tests
zig build test

# Format code
zig fmt src/**/*.zig

# Check for TODOs
make todo
```

## Development Commands

```bash
# Parse EVTX file to XML (default)
make sample FILE=samples/system.evtx

# Parse to JSON
make json FILE=samples/system.evtx

# Parse to JSONL
make jsonl FILE=samples/system.evtx

# Compare output with Rust evtx_dump (first record)
make compare-first FILE=samples/system.evtx

# Compare all records
make compare-all FILE=samples/system.evtx

# Extract and compare specific record
make record FILE=samples/system.evtx RID=1234  # by EventRecordID
make record FILE=samples/system.evtx N=5       # by ordinal position
```

## Architecture

> **Detailed documentation**: See [docs/architecture.md](docs/architecture.md) for diagrams and performance analysis.

### Two-Stage Architecture

The parser uses a two-stage approach with type-safe template caching:

1. **Stage 1 — Parse to IR**: Parse BinXML into `Template` (with `Placeholder` nodes), then instantiate to `ElementTree` (fully resolved)
2. **Stage 2 — Render**: Serialize `ElementTree` to XML/JSON in one pass

### Type-Safe Wrapper Types

| Type | Contains Placeholder? | Purpose |
|------|----------------------|---------|
| `Template` | Yes | Cached template definition with substitution markers |
| `ElementTree` | No (guaranteed) | Resolved output, accepted by renderers |

### Core Components

**Parser Structure (`src/parser/evtx/`):**
- `format.zig`: EVTX file/chunk/record structures with magic "ElfFile\x00"
- `parser.zig`: Main parser managing file/chunk/record iteration
- `output.zig`: OutputWriter for streaming XML/JSON/JSONL results

**Binary XML Parser (`src/parser/binxml/`):**
- `parser.zig`: Main parser with `parseRecord()` → `ElementTree`
- `context.zig`: `Template`, `ElementTree`, cache, and instantiation logic
- `types.zig`: Binary format structs (headers, descriptors)
- `tokens.zig`: Token constants (0x0c TemplateInstance, 0x0d/0x0e Substitutions)

**IR (`src/parser/ir.zig`):**
- `Node`: Element | Text | Value | Placeholder | CharRef | ...
- `Placeholder`: Only exists in cached `Template`, never in `ElementTree`

### Parser Flow

1. **File Level**: Read file header, validate magic and checksums
2. **Chunk Level**: Iterate 64KB chunks, reset per-chunk arena and cache
3. **Record Level**: Parse event records containing Binary XML fragments
4. **Binary XML**:
   - Template definitions → `Template` (with `Placeholder` nodes)
   - Template instances → `template.instantiate()` → `ElementTree`
5. **Output**: Render `ElementTree` to XML/JSON (Placeholder case is `unreachable`)

### Performance

Clone + Resolve approach is **1.65x faster** than re-parsing templates:
- Templates parsed once, cached as `Template` with `Placeholder` nodes
- Each instance: clone tree + resolve placeholders (mostly memcpy)
- Avoids repeated token dispatch and parsing overhead

### Concurrent worker engine (`src/parser/evtx/worker.zig`)

- Workers and the chunk-reader run as `io.concurrent` futures, not raw
  `std.Thread.spawn`. This keeps the parser portable across `std.Io`
  implementations.
- Output handoff uses `std.Io.Queue(EmittedRecord)`: one per chunk in
  ordered mode (chained through a meta queue to preserve order) or one
  shared queue in unordered mode.
- Cancellation is implicit via `defer future.cancel(io) catch {}` at every
  spawn site. There is no shared `cancelled` / `broken_pipe` / `fatal_error`
  atomic; errors propagate through `Future.await`.

## Current State

The parser implements basic EVTX file and chunk parsing with partial Binary XML support. See TODO.md for pending implementation items including:
- Complete Binary XML token framework
- Full template system implementation
- Type conversions (GUID, FILETIME, SID, etc.)
- Output parity with evtx_dump

## Testing Approach

The project uses comparison testing against the Rust `evtx_dump` tool:
- XML normalization for fair comparison (expanding self-closing tags, removing prologs)
- Record-by-record comparison via Python diff script
- Test samples in `samples/` directory covering various EVTX file types

## Core principles
- Deterministic paths only: For each token and structure, parse exactly the fields the spec mandates in that context. No probing, no retrying, no alternative interpretations.
- Minimal explicit context: If the spec defines multiple valid encodings depending on nesting (e.g., Binary XML substitution vs normal element start), capture that as an explicit, single-bit context (e.g., `ParseContext` in [src/binary_xml.zig](mdc:src/binary_xml.zig)). Do not infer context from bytes by trying multiple parses.
- No fallbacks: If parsing fails under the selected spec-defined path, propagate the error. Do not re-parse with a different interpretation.
- No heuristics: Do not "peek and guess" or validate by attempting different layouts. If it is not disambiguated by spec and state, the input is invalid.
- Span checks are authoritative: Sizes (e.g., `data_size`) define the canonical boundary of structures. Always compute `expected_end` deterministically and verify cursor position matches. Mismatches are errors.
