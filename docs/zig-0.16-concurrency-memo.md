# Zig 0.16 Concurrency Memo

Adapted from Hermes repo-specific analysis for `zig-evtx`.

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
