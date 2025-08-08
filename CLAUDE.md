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

### Core Components

**Parser Structure (`src/parser/evtx.zig`):**
- `EvtxParser`: Main parser managing file/chunk/record iteration
- `FileHeader`: EVTX file header with magic "ElfFile\x00"
- `Chunk`: 64KB chunks containing event records
- `EventRecord`: Individual event with ID, timestamp, and Binary XML data
- Output implementations for XML/JSON/JSONL rendering

**Binary XML Parser (`src/parser/binxml.zig`):**
- `Reader`: Low-level token reader for Binary XML streams
- `Context`: Manages parsing state including template cache and string tables
- Token-based parser implementing Microsoft's Binary XML format used in EVTX
- Handles elements, attributes, values, substitutions, and template instances
- Key tokens: 0x0f (Fragment), 0x01/0x41 (OpenStart), 0x0c (TemplateInstance), 0x0d/0x0e (Substitutions)

**Utilities (`src/parser/util.zig`):**
- XML escaping and UTF-16 LE to UTF-8 conversion
- FILETIME/SystemTime formatting
- GUID, SID, and binary data formatting

### Parser Flow

1. **File Level**: Read file header, validate magic and checksums
2. **Chunk Level**: Iterate 64KB chunks, each with string table and template definitions
3. **Record Level**: Parse event records containing Binary XML fragments
4. **Binary XML**: Token-based parsing with template expansion and substitution handling
5. **Output**: Render parsed events to XML/JSON with proper formatting

### Key Implementation Details

- **Template System**: Templates are cached per-chunk and referenced by GUID. Template instances apply substitutions to template definitions.
- **String Tables**: Each chunk maintains offset-based string tables for name deduplication
- **Substitutions**: Values are injected into templates using normal (0x0d) and optional (0x0e) substitution tokens
- **Has-More Flag**: Tokens with 0x40 flag indicate continuation (e.g., long strings split across multiple value tokens)

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