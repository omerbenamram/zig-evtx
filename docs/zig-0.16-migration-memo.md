# Zig 0.16 Migration Memo

Adapted from Hermes research for use inside this repository.

This repo-owned memo exists so `zig-evtx` workers can discover the migration plan
without depending on hidden Hermes state. All validation examples in this mission
should use the explicit Zig 0.16 toolchain at
`/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig`.

## Main repository-level migration costs

1. `std.Io` is now an injected interface
2. `std.process.Init` is the preferred startup boundary
3. args and environment should be explicit inputs
4. `@Type` removal may affect metaprogramming-heavy code
5. `@cImport` deprecation may push more work into `build.zig`
6. allocator/container ownership should become more explicit

## Recommended repo migration order

1. Upgrade build integration and dependency wiring
2. Convert CLI/test entrypoints to Zig 0.16 startup and I/O boundaries
3. Thread explicit `std.Io` through app/runtime APIs
4. Fix legacy I/O, env, and process-state assumptions
5. Audit allocator/container and packed/FFI hot spots if encountered

## zig-evtx-specific runtime seams

- Keep CLI and snapshot entrypoints responsible for `std.Io` initialization,
  process arguments, environment lookups, and process-facing failure policy.
- Keep parser and renderer code backend-agnostic; prefer injected reader/writer
  capability over helpers rediscovering runtime state.
- Treat `src/parser/evtx/output.zig` as the main output boundary: local scratch
  buffering is preferred over spreading buffering setup across unrelated code.
- If concurrency changes are required, align them with the separate
  `docs/zig-0.16-concurrency-memo.md` guidance instead of adding ad-hoc worker
  ownership rules.

## Fast triage checklist

- grep for `@Type`
- grep for `@cImport`
- grep for `std.fs.cwd`, `std.fs.File.stdout`, `reader(&buf)`, `writer(&buf)`
- grep for ambient args/env helpers
- grep concurrency/sync code that should be aligned with `std.Io` ownership

## Validation path for this repo

- `"/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig" build -Dtarget=native -Doptimize=ReleaseFast -Duse-c-alloc=false -Dwith-python=false`
- `"/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig" build test -Dtarget=native -Doptimize=Debug -Duse-c-alloc=false`
