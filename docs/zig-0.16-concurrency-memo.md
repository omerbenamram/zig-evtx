# Zig 0.16 Concurrency Memo

Adapted from Hermes repo-specific analysis for `zig-evtx`.

This memo is stored in the repository so `zig-evtx` concurrency guidance remains
discoverable without hidden Hermes state. Validation and examples should assume
the explicit mission toolchain path
`/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig`.

## Why this area matters

The current concurrency path in `src/parser/evtx/worker.zig` is the sharpest integration seam for this mission because it combines:
- explicit `std.Io` ownership
- worker lifecycle cleanup
- ordered/unordered output guarantees
- cancellation and broken-pipe handling

## Guidance for this repo

- Prefer explicit `io: std.Io` plumbing over hidden global/runtime state.
- Keep stdout/process-facing output ownership coherent.
- Preserve ordered mode as equivalent to sequential semantics.
- Preserve unordered mode as the same logical record set.
- Ensure early sink failure, broken pipe, and `max_records` all stop work cleanly.

## Recommended tightening themes

- make output ownership clearer
- make cancellation and cleanup structured
- keep memory/backpressure bounded where possible
- align concurrency fixes with documented runtime-shell vs pure-core boundaries

## zig-evtx worker-specific reminders

- Keep stdout/process-facing writes owned coherently; prefer one runtime-owned
  output path over workers rediscovering stdout independently.
- Preserve the repo contract that ordered mode matches sequential semantics while
  unordered mode may reorder records but not change the logical record set.
- When fixing Zig 0.16 runtime issues, thread explicit `io: std.Io` from the
  executable boundary down rather than introducing hidden globals in
  `src/parser/evtx/worker.zig`.
