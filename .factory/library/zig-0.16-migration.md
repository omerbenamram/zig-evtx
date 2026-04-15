# Zig 0.16 Migration

Repo-local Zig 0.16 migration guidance derived from Hermes research.

**What belongs here:** migration patterns, Zig 0.16 breakpoints, repo-specific guidance workers should follow.

---

## Core move

Thread `io: std.Io` from the executable boundary downward.

At process entrypoints, prefer:

```zig
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;
}
```

## Important Zig 0.16 migration breakpoints

- `std.Io` replaces ambient/legacy I/O assumptions
- process startup is centered around `std.process.Init`
- args and environment should be handled at the process boundary
- `@Type` is gone in favor of specific type-construction builtins
- `@cImport` migration may require build-system changes
- allocator/container APIs continue pushing toward explicit ownership

## Mechanical smells to remove

Search for and eliminate legacy patterns such as:
- `std.fs.cwd()`
- `std.fs.File.stdout()`
- `std.fs.File.stderr()`
- `file.reader(&buf)`
- `file.writer(&buf)`
- `file.close()` without explicit `io`

## Repo-specific guidance

- Keep runtime-shell behavior at CLI/snapshot boundaries.
- Do not re-derive process state deep in parser helpers.
- Preserve deterministic parsing and no-heuristics rules from `CLAUDE.md`.
- Treat concurrency/output ownership as a first-class Zig 0.16 migration seam, not only a bugfix seam.
