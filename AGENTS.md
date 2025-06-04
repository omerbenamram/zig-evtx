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

generates `python_first.xml` and `zig_first.xml` for inspection. These artifacts
are listed in `.gitignore` and can be safely removed after use.
- `Evtx`, `ChunkHeader`, `Record` and `Template` are defined in `src/evtx.zig` and manage file parsing.
- `BXmlNode` and its node variants live in `src/bxml_parser.zig` and form the active binary XML parser.
- `SubstitutionArray` and `TemplateProcessor` in `src/template_processor.zig` handle variant values and apply template substitutions.
- Older node implementations from `nodes.zig` and the removed `RootNode` type are no longer used.

## Environment Setup
1. Activate the virtual environment:
   ```bash
   source .venv/bin/activate
   ```
2. Install Python dependencies using `uv`:
   ```bash
   uv add <package>
   ```
3. Use `uv run` to execute Python tools.

## Running Tests
- **Zig unit tests:** `zig test src/test_runner.zig` (INCOMPLETE - these do NOT indicate parser is currently working, we need to rely on comparison scripts.)
- **Zig/Python comparison:** `uv run python diff_first_record_xml.py`

Run `diff_first_record_xml.py` to see a unified diff of the first record XML
between the reference Python parser and the Zig implementation. The script also
writes `python_first.xml` and `zig_first.xml` for further inspection.

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
- Use `Block.unpackWstring` (and related helpers in `src/binary_parser.zig`) for
  all UTF‑16 string parsing instead of ad‑hoc conversions. Keep UTF‑16 logic in
  that file so other modules remain focused on higher level parsing.
- Apply template substitutions via `TemplateProcessor` (or `parseRecordXml`) and
  avoid returning hard coded placeholder XML when record parsing fails.
- When debugging template issues, avoid inserting guessed values or partial XML. Investigate the root cause instead.
- Prefer rendering templates with actual substitution values. The Python
  `evtx_template_readable_view` is helpful for exploration but does **not**
  represent the real XML, so tests comparing output should rely on the fully
  substituted XML strings.

## Template Caching
- Each `ChunkHeader` maintains an `AutoHashMap(u32, Template)` storing parsed
  templates. `loadTemplates` populates this cache once per chunk and `getTemplate`
  retrieves entries by ID. Record parsing should first consult this map before
  attempting to parse a resident template.
- When a record provides an updated resident template, use
  `fetchPut` on the map and free the previous template's `xml_format` to avoid
  leaks.

## Memory Leaks
- The comparison test (`zig run test_template_comparison.zig`) must report no
  leaked addresses when using `GeneralPurposeAllocator`.
- Always deinitialize `ChunkHeader` and free template XML strings when they are
  no longer needed.

## Pull Request Guidelines
- When drafting the PR description, include a brief example or explanation of
  how the changes move the Zig parser closer to feature parity with the
  reference Python implementation. This helps reviewers track progress toward
  Python compatibility.

