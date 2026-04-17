# std.Io concurrency and testing implementation plan for zig-evtx

## Status note

A commit of the current working state is blocked because `/home/omerba/Work/zig-evtx` does not contain a `.git` directory. This plan is saved directly in the repo tree for delegated execution.

## Goal

Leverage Zig 0.16 `std.Io` to harden the concurrent parsing path, remove remaining 0.15-style writer and reader assumptions from the concurrency and test stack, and add testing coverage that proves deterministic behavior, bounded cancellation, and snapshot stability.

## Step 1. Establish the Zig 0.16 std.Io seam for concurrency and test code

Objective:
Create one concrete migration seam for the concurrency engine and test harness so the code stops depending on 0.15-era `.interface` access and concrete `*std.Io.Writer` assumptions. Keep the public parser behavior stable while making `std.Io` initialization and handle passing explicit.

Files:
- `src/parser/evtx/output.zig`
- `src/parser/evtx/format.zig`
- `src/parser/evtx/parser.zig`
- `src/parser/err.zig`
- `src/parser/render_xml.zig`
- `src/parser/render_json.zig`
- `src/parser/util_string.zig`
- `src/parser/util_simd.zig`
- `src/test/snapshot_tests.zig`
- `src/main.zig`
- `src/snapshot_tool.zig`
- `docs/plans/zig-0.16-upgrade.md`

Tests:
- `zig build test`
- `zig build snapshot -- --help`
- `zig build run -- --help`
- Focused compile check for files that currently use `.interface`, `readSliceAll`, `writeAll`, `flush`, and `OutputWriter.initSerializeOnly`

Execution notes:
- Start from the existing 0.16 migration doc and treat `src/parser/evtx/output.zig` plus `src/parser/evtx/format.zig` as the primary seam.
- Replace `OutputWriter.dest: ?*std.Io.Writer` and `std.Io.Writer.Allocating` assumptions with a 0.16-compatible abstraction that keeps scratch buffering local to `OutputWriter`.
- Remove the reader shape probe in `src/parser/evtx/format.zig` at the `@hasField(ReaderType, "interface")` seam and switch to one deterministic read path.
- Keep parser entry points generic over the minimum reader and writer capability needed.
- Update `src/main.zig`, `src/snapshot_tool.zig`, and test helpers to initialize and pass `std.Io` the same way, so concurrency and snapshot code share one model.
- Do not change parser semantics in this step. Exit this step only when the build compiles with one coherent `std.Io` pattern.

## Step 2. Refactor the concurrent worker engine around explicit std.Io ownership and ordered output control

Objective:
Make the concurrent parser path explicit about I/O ownership, cancellation, output draining, and ordering so it is ready for Zig 0.16 and easier to reason about under delegation. Preserve the current `ordered` and `unordered` modes while reducing hidden global coupling.

Files:
- `src/parser/evtx/worker.zig`
- `src/parser/evtx/parser.zig`
- `src/main.zig`
- `src/parser/evtx/output.zig`
- `src/logger.zig`

Tests:
- `zig build test --summary all`
- CLI smoke tests on samples:
  - `zig build run -- samples/security.evtx -n 20`
  - `zig build run -- -o jsonl samples/security.evtx -n 20 -t 1`
  - `zig build run -- -o jsonl samples/security.evtx -n 20 -t 4`
  - `zig build run -- -o jsonl --unordered samples/security.evtx -n 20 -t 4`
- Pipe handling smoke test:
  - `zig build run -- samples/security.evtx -n 100 | head`

Execution notes:
- `src/parser/evtx/worker.zig` already mixes explicit `std.Io`, thread spawning, atomics, ordered slots, and a fallback to `std.Options.debug_threaded_io.?.io()`. Replace that global fallback with injected I/O state created at the entrypoint or parser boundary.
- Split responsibilities inside `worker.zig` into clearly delegated units: chunk read scheduling, worker serialization, ordered drain, unordered direct write, cancellation and fatal error propagation.
- Keep `parseConcurrent` as the orchestration layer, but give it explicit inputs for stdout sink and I/O runtime rather than re-deriving them internally.
- Preserve the current slot-based ordered drain design for the first pass. Improve its invariants before changing the algorithm.
- Add assertions or internal checks around slot readiness, emitted counts, and `max_records` cutoff behavior to prevent off-by-one races.
- Exit this step when the concurrent path works in both ordered and unordered modes with the same CLI surface.

## Step 3. Make concurrency results deterministic and testable with chunk-level and record-level invariants

Objective:
Turn the concurrency engine into a component that can be tested without depending only on stdout side effects. Add a deterministic collection mode or injectable sink so tests can verify ordering, record limits, skipped records, and cancellation behavior directly.

Files:
- `src/parser/evtx/worker.zig`
- `src/parser/evtx/parser.zig`
- `src/parser/evtx/output.zig`
- `src/test/util.zig`
- New test file: `src/test/concurrency_tests.zig`
- `src/main.zig`

Tests:
- Add unit tests covering:
  - ordered mode preserves sequential output equivalence
  - unordered mode emits the same record set as sequential mode
  - `skip_first` and `max_records` produce the same selected records in single-threaded and multi-threaded runs
  - cancellation after reaching `max_records` stops further emission
  - broken-pipe and write-failure handling stops cleanly
- Run:
  - `zig build test`
  - targeted test filters for the new concurrency suite if available

Execution notes:
- Right now the concurrent path is hard to verify because writing happens through stdout-oriented code paths in `worker.zig`.
- Introduce a delegated seam, either an injected sink interface or a serialize-to-buffer collection path, that lets tests capture emitted records without shell pipes.
- Use sequential `EvtxParser.parse` output as the canonical oracle for ordered mode.
- For unordered mode, compare normalized record sets keyed by `EventRecordID` or full serialized records after sorting, depending on output format.
- Reuse real sample EVTX data where possible, especially `samples/security.evtx`, because current worker tests already depend on it.
- Keep the production hot path efficient. Test-only helpers should live under `src/test` or be compiled out when possible.
- Exit this step when concurrency correctness is asserted in-process rather than inferred only from manual CLI runs.

## Step 4. Upgrade the snapshot and regression harness to exercise std.Io and concurrency together

Objective:
Expand the snapshot tooling so it validates both the new `std.Io` path and the concurrency engine. Snapshot tests should cover sequential and concurrent execution, XML and JSON output, and deterministic normalization rules.

Files:
- `src/test/snapshot_tests.zig`
- `src/snapshot_tool.zig`
- `build.zig`
- `tests/snapshots/` expected outputs as needed
- New helper if needed: `src/test/concurrency_snapshot_util.zig`
- Documentation update in `README.md` or `docs/architecture.md` if test invocation changes

Tests:
- `zig build snapshot`
- `zig build snapshot -- --update` only when intentionally refreshing outputs
- Add snapshot modes for:
  - sequential XML
  - sequential JSON
  - concurrent ordered XML
  - concurrent ordered JSON
  - optional concurrent unordered normalized comparison path
- Ensure `zig build test` still exercises snapshot helper logic even when sample files are missing by keeping skip behavior explicit

Execution notes:
- `src/test/snapshot_tests.zig` already uses `std.Io.Threaded`, file readers, `OutputWriter.initSerializeOnly`, and direct file writes. This is the right place to enforce the final `std.Io` style.
- Extend the snapshot harness so a test definition can choose execution mode, thread count, and normalization rule.
- For ordered concurrent mode, expected snapshots can stay byte-for-byte identical to sequential output.
- For unordered mode, add normalized comparison rather than raw byte comparison. Keep this as a separate assertion path so non-deterministic order does not corrupt stable snapshots.
- If build graph changes are needed, keep `zig build snapshot` as the stable entrypoint and only extend CLI args.
- Exit this step when snapshot runs validate both parser correctness and the std.Io-backed concurrency path.

## Step 5. Lock in performance, documentation, and delegated execution boundaries

Objective:
Finish the migration by documenting the execution model, adding benchmark and regression guardrails, and defining a clean delegation map so each implementation slice can be handed off independently without semantic drift.

Files:
- `docs/plans/zig-0.16-upgrade.md`
- `docs/architecture.md`
- `build.zig`
- `src/bench_serialize.zig`
- `src/bench_utf_zbench.zig`
- `README.md`
- Optional new doc: `docs/plans/std-io-concurrency-testing-rollout.md`

Tests:
- Full validation pass:
  - `zig build test`
  - `zig build snapshot`
  - `zig build run -- samples/security.evtx -n 100 -t 1`
  - `zig build run -- samples/security.evtx -n 100 -t 4`
  - `zig build run -- -o jsonl samples/security.evtx -n 100 -t 4 --unordered`
- Bench or timing smoke checks once `zbench` is 0.16-ready:
  - `zig build bench-serialize`
  - `zig build bench-zbench`

Execution notes:
- Document the final threading model in `docs/architecture.md`, including chunk scheduling, output slot draining, cancellation, and the role of `std.Io` initialization.
- Document benchmark status explicitly if `zbench` remains blocked on Zig 0.16. Do not let benchmark tooling ambiguity hide parser readiness.
- Capture a delegated task map in the plan or architecture docs. Suggested work split:
  - writer and reader seam migration
  - worker engine refactor
  - concurrency unit tests
  - snapshot harness extension
  - documentation and benchmark restoration
- Define completion criteria in docs: sequential and concurrent paths agree, snapshot coverage passes, broken-pipe behavior is clean, and test entrypoints remain stable.
- Exit this step only when the repo contains enough documentation and test coverage for another agent to implement or maintain the system without rediscovering the architecture.
