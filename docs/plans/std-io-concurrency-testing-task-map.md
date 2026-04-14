# std.Io concurrency/testing delegated task map

## Purpose
Resume the 5-step std.Io concurrency/testing plan after stabilization with task slices that are safe to hand off independently and that minimize overlap in the parser, worker, and snapshot paths.

## Current codebase read on plan status
- Step 1 is partially reflected in the tree. `src/parser/evtx/output.zig`, `src/main.zig`, and `src/snapshot_tool.zig` already use Zig 0.16 `std.Io` shapes and `OutputWriter.initSerializeOnly` now keeps scratch buffering local.
- The plan text still treats Step 3 as future work, but `src/test/concurrency_tests.zig` already exists and `src/parser/evtx/parser.zig` already exposes `collectConcurrent` and `collectConcurrentWithFailure` entrypoints.
- `src/parser/evtx/worker.zig` is still the main integration hotspot. It owns chunk scheduling, serialization, ordered drain, direct writes, cancellation, and pipe handling in one file.
- Snapshot coverage is still record-level and sequential in `src/test/snapshot_tests.zig`. It does not yet model execution mode, thread count, or unordered normalization.
- Remaining 0.15-style seams still exist outside the core 5-step seam, especially `src/evtx_pydust_impl.zig`, `src/bench_serialize.zig`, `src/bench_utf_zbench.zig`, and `src/parser/value_format.zig`.

## Recommended first implementation step once stabilization is green
Implement Step 2 first.

Reason:
- Step 2 is the narrowest safe continuation point after stabilization.
- Step 3 already depends on worker collection hooks that exist, but those hooks should be validated against the final worker ownership model before more tests are added.
- Step 4 snapshot expansion depends on Step 2 invariants for ordered and unordered execution.
- Step 2 gives one stable concurrency boundary for all later delegated work.

## Safe delegated slices

### Slice A. Lock the explicit I/O ownership boundary for concurrent execution
Maps to: Step 2

Scope:
- `src/parser/evtx/worker.zig`
- `src/parser/evtx/parser.zig`
- `src/main.zig`

Deliverables:
- Keep `worker.parseConcurrent` driven only by injected `IoRuntime` and parser options.
- Remove any remaining hidden runtime derivation or global fallback in the worker path.
- Make the parser boundary the only place that constructs the runtime used by concurrent stdout writes.
- Preserve the current CLI surface and sequential path behavior.

Completion checks:
- `zig build test --summary all`
- `zig build run -- samples/security.evtx -n 20`
- `zig build run -- -o jsonl samples/security.evtx -n 20 -t 1`
- `zig build run -- -o jsonl samples/security.evtx -n 20 -t 4`
- `zig build run -- -o jsonl --unordered samples/security.evtx -n 20 -t 4`
- `zig build run -- samples/security.evtx -n 100 | head`

Delegation notes:
- This slice should avoid adding new test harness abstractions beyond what is required to stabilize worker interfaces.
- Treat `src/main.zig` changes as adapter-only.

### Slice B. Split worker responsibilities without changing output semantics
Maps to: Step 2

Scope:
- `src/parser/evtx/worker.zig`
- optional small touch in `src/logger.zig` if logging APIs need cleaner assertions

Deliverables:
- Separate chunk read scheduling, worker serialization, ordered drain, unordered write path, and fatal/cancel handling into internal helpers or small structs.
- Keep slot-based ordered draining intact for this pass.
- Add internal assertions around slot readiness, span bounds, emitted count, and `max_records` cutoff behavior.

Completion checks:
- same Step 2 checks
- ensure no ordered vs unordered output regression on `samples/security.evtx`

Delegation notes:
- This slice is best done by one agent because `worker.zig` is already tightly coupled.
- Do not bundle snapshot or new public API work into this slice.

### Slice C. Reconcile and finish in-process concurrency verification
Maps to: Step 3

Scope:
- `src/parser/evtx/worker.zig`
- `src/parser/evtx/parser.zig`
- `src/test/concurrency_tests.zig`
- `src/test/util.zig`
- `src/parser/evtx/output.zig` only if sink shape needs a minimal extension

Deliverables:
- Audit the existing collection path used by `collectConcurrent` and `collectConcurrentWithFailure` against the finalized Step 2 worker model.
- Fill any missing implementation for `CollectedOutput`, emitted record metadata, and failure injection support.
- Expand tests to cover ordered equivalence, unordered set equality, `skip_first`, `max_records`, cancellation, and clean broken-pipe/write-failure stop behavior.

Completion checks:
- `zig build test`
- targeted concurrency test filter if available

Delegation notes:
- This slice should consume Step 2 as a dependency and avoid rewriting worker scheduling again.
- If a sink abstraction is needed, keep it internal to worker/output code and shaped for tests first.

### Slice D. Extend snapshot coverage to concurrent modes
Maps to: Step 4

Scope:
- `src/test/snapshot_tests.zig`
- `src/snapshot_tool.zig`
- `build.zig`
- `tests/snapshots/`
- optional new helper `src/test/concurrency_snapshot_util.zig`

Deliverables:
- Add test definition fields for execution mode, thread count, and normalization rule.
- Keep sequential snapshots byte-stable.
- Add concurrent ordered snapshot cases for XML and JSON.
- Add a separate normalized comparison path for unordered mode instead of byte snapshots.
- Keep missing-sample skip behavior explicit.

Completion checks:
- `zig build snapshot`
- `zig build test`
- `zig build snapshot -- --update` only when refreshing expected outputs intentionally

Delegation notes:
- This slice should not alter worker semantics.
- Snapshot expected files should be refreshed only after ordered concurrent output is proven equivalent to sequential output.

### Slice E. Finish remaining std.Io cleanup outside the worker/snapshot seam
Maps to: residual Step 1 cleanup and Step 5 prep

Scope:
- `src/evtx_pydust_impl.zig`
- `src/bench_serialize.zig`
- `src/bench_utf_zbench.zig`
- `src/parser/value_format.zig`
- docs touched by final seam notes

Deliverables:
- Remove remaining `.interface` and old writer assumptions in secondary tooling.
- Align bench and embedding entrypoints with the same explicit `std.Io` model used by CLI and snapshots.
- Document any external package blockers, especially `zbench` readiness.

Completion checks:
- compile the affected entrypoints that still build under current dependencies
- do not block core parser stabilization on benchmark package issues

Delegation notes:
- This slice is intentionally separated from Steps 2 to 4 because it overlaps with tooling, bindings, and benchmark dependencies.

### Slice F. Final rollout and documentation lock
Maps to: Step 5

Scope:
- `docs/plans/zig-0.16-upgrade.md`
- `docs/architecture.md`
- `README.md`
- `build.zig`
- optional `docs/plans/std-io-concurrency-testing-rollout.md`

Deliverables:
- Document the final threading model, cancellation behavior, ordered drain, and std.Io initialization boundary.
- Record stable test and snapshot entrypoints.
- Record benchmark status and any temporary package constraints.
- Preserve this delegated map or fold it into the architecture docs once implementation settles.

Completion checks:
- full validation pass from the 5-step plan

## Overlap and conflict risk by step

### Highest overlap
- Step 2 and Step 3
  - Shared files: `src/parser/evtx/worker.zig`, `src/parser/evtx/parser.zig`, `src/parser/evtx/output.zig`
  - Risk: test seam work can force a second redesign of worker ownership or emission semantics if Step 2 is still moving.
  - Control: freeze worker interfaces at the end of Slice B before adding more Step 3 logic.

- Step 1 residual cleanup and Step 4
  - Shared files: `src/test/snapshot_tests.zig`, `src/snapshot_tool.zig`, `build.zig`
  - Risk: snapshot harness can encode an I/O pattern that later secondary-tool cleanup changes again.
  - Control: finish the secondary `std.Io` cleanup for snapshot-adjacent code before large snapshot harness expansion.

### Medium overlap
- Step 2 and Step 4
  - Shared files: `src/main.zig`, `src/parser/evtx/output.zig`, snapshot helpers through execution-mode assumptions
  - Risk: concurrent snapshot expectations drift if ordered drain semantics or cancellation behavior changes.
  - Control: no concurrent snapshot refresh until ordered mode is stable and concurrency tests pass.

- Step 4 and Step 5
  - Shared files: `build.zig`, docs, snapshot invocation docs
  - Risk: documentation gets stale if build entrypoints move during snapshot work.
  - Control: update docs only after snapshot CLI shape stabilizes.

### Low overlap
- Step 3 and Step 5
  - Mostly docs and final validation coupling.
- Residual Step 1 cleanup and Step 2
  - Overlap is low if secondary tool cleanup stays out of `worker.zig`.

## Suggested handoff order
1. Slice A, explicit concurrent I/O boundary
2. Slice B, worker internal refactor and invariants
3. Slice C, reconcile and complete concurrency tests around the stabilized worker model
4. Slice D, snapshot concurrency expansion
5. Slice E, secondary tool std.Io cleanup and benchmark/binding alignment
6. Slice F, documentation and rollout lock

## Exact next task to delegate first after stabilization
Task: Step 2 Slice A plus the minimal part of Slice B needed to make `src/parser/evtx/worker.zig` internally coherent.

Task brief:
- Refactor concurrent execution so `parseConcurrent` consumes only injected `IoRuntime` and parser options.
- Keep stdout ownership and broken-pipe handling explicit at the parser entrypoint boundary.
- Preserve ordered and unordered output behavior.
- Add internal assertions for ordered slot drain bounds and `max_records` cancellation invariants.
- Do not expand snapshot coverage or benchmark code in this task.

Why this first:
- It isolates the highest-risk concurrency file before more tests and snapshots depend on it.
- It minimizes merge conflicts by postponing test-harness and snapshot edits until worker semantics settle.
- It creates the cleanest base for delegated follow-on work.
