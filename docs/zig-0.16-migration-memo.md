# Zig 0.16 Migration Memo

Adapted from Hermes research for use inside this repository.

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

## Fast triage checklist

- grep for `@Type`
- grep for `@cImport`
- grep for `std.fs.cwd`, `std.fs.File.stdout`, `reader(&buf)`, `writer(&buf)`
- grep for ambient args/env helpers
- grep concurrency/sync code that should be aligned with `std.Io` ownership
