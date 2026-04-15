# Architecture

How the system works at a high level.

**What belongs here:** major components, ownership boundaries, runtime/data flow, invariants workers must preserve.
**What does NOT belong here:** step-by-step task plans or command manifests.

---

## System shape

`zig-evtx` is a Zig EVTX parser with:
- a CLI entrypoint in `src/main.zig`
- a snapshot-testing tool in `src/snapshot_tool.zig`
- parser and rendering core under `src/parser/`
- optional Python bindings via `pydust.build.zig`, `src/evtx_pydust.zig`, and `src/evtx_pydust_impl.zig`

The repo is migrating onto Zig 0.16 and should treat Zig 0.16 behavior as the baseline, not a compatibility afterthought.

## Runtime-shell vs pure-core boundary

Entry points own process-facing concerns:
- Zig startup and toolchain-facing configuration
- `std.Io` initialization and injected I/O handles
- stdout/stderr/file-handle setup
- CLI argument handling and env-driven logging policy
- process-facing failure policy such as broken-pipe behavior

Parser/render core should remain backend-agnostic:
- parse EVTX/BinXML deterministically
- operate on explicit inputs rather than ambient process state
- avoid re-deriving runtime shell state deep in helpers
- preserve deterministic parsing and error propagation rules from `CLAUDE.md`

## Concurrency boundary

Concurrent parsing lives at the parser runtime layer, especially `src/parser/evtx/worker.zig`.

Critical invariants:
- cancellation and early-stop behavior must be coordinated explicitly
- ordered mode must preserve sequential semantics
- unordered mode may reorder records but must preserve the logical record set
- process-facing write failures must stop work cleanly
- worker lifecycle cleanup must complete even on early error

The mission should prefer a single coherent ownership model around `std.Io`, cancellation, and output emission rather than patchwork ad-hoc threading fixes.

## Validation surfaces

Primary validation surfaces are:
- Zig build graph
- Zig test graph
- CLI output modes (`xml`, `json`, `jsonl`)
- snapshot tool
- concurrency/runtime behavior
- Python build/test flow if touched by the mission

## Imported Hermes guidance

The repo-local mission infrastructure should preserve Hermes-derived knowledge in two forms:
- reusable worker skill guidance under `.factory/skills/`
- supporting migration/concurrency memos in repo docs or `.factory/library/`

Workers should not rely on hidden external Hermes state once the mission artifacts are created.
