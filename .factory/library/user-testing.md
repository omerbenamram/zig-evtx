# User Testing

Validation surface findings and runtime testing guidance.

**What belongs here:** testable surfaces, tools, setup requirements, concurrency classification, gotchas.
**What does NOT belong here:** implementation plans.

---

## Validation Surface

### CLI
- Primary surface for this mission.
- Validate with the explicit Zig 0.16 binary.
- Representative commands:
  - `"/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig" build run -- -t 1 -n 1 -o xml samples/system.evtx`
  - `"/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig" build run -- -t 1 -n 1 -o json samples/system.evtx`
  - `"/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig" build run -- -t 1 -n 1 -o jsonl samples/system.evtx`

### Test graph
- Hard gate: `"/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig" build test`

### Snapshot tool
- Validate with `"/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig" build snapshot -- --test <name>`

### Python integration
- Conditional surface only if mission changes Python build/runtime integration.
- Suggested commands:
  - `make py-editable ZIG="/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig"`
  - `make py-test ZIG="/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig"`

## Validation Concurrency

### CLI / shell validation
- Max concurrent validators: **5**
- Rationale:
  - 24 logical CPUs
  - ~34 GiB available memory during dry run
  - negligible resource delta from `zig build test` and CLI smoke validation
  - CLI validation is lightweight relative to machine headroom

## Known gotchas

- Default PATH `zig` may still point at 0.15.x in some shells; always prefer the explicit Zig 0.16 path.
- Python validation is optional unless touched by mission work.
- `zig build test` currently prints expected `worker ... WriteFailed` noise while exercising sink-failure concurrency tests; use the command exit code and targeted evidence files as the source of truth.

## Flow Validator Guidance: knowledge-import

- Scope is repo-local artifact validation only: inspect `.factory/skills/`, `.factory/library/`, `README.md`, and mission contract/state files as needed.
- Do not modify implementation code, docs, or build files while validating these assertions.
- Write only to the assigned flow report path under `.factory/validation/<milestone>/user-testing/flows/` and the assigned evidence directory under the mission folder.
- This surface is safe to run concurrently because assertions are satisfied by read-only inspection of version-controlled artifacts; avoid overlapping writes to the same report or evidence paths.

## Flow Validator Guidance: zig-0-16-runtime CLI

- Validate the real user-facing CLI and related build/snapshot commands from `/home/omerba/zig-evtx`.
- Always use the explicit Zig 0.16 binary at `"/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig"`.
- Keep writes within the assigned flow report path under `.factory/validation/<milestone>/user-testing/flows/` and the assigned evidence directory under the mission folder.
- `zig build`, `zig build test`, and `zig build snapshot` share repo-local cache/output paths by default, so treat the repo as a shared mutable resource unless an isolated cache/output directory is explicitly assigned.
- Without isolated cache/output directories, serialize build-driving validators for this surface. Read-only artifact inspection may run separately, but do not run multiple build-driving validators against the same repo checkout at once.

## Flow Validator Guidance: bugbot-fixes CLI

- Validate the real CLI/runtime surface from `/home/omerba/zig-evtx` using the explicit Zig 0.16 binary at `"/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig"`.
- Focus on the concurrency and logging contract assertions for ordered output, unordered output, skip/max selection, early sink failure handling, and verbosity behavior.
- Keep writes within the assigned flow report path under `.factory/validation/<milestone>/user-testing/flows/` and the assigned evidence directory under the mission folder.
- Build-driving commands (`zig build`, `zig build test`, `zig test`, or any command that reuses the repo-local Zig cache/output directories) must be serialized unless isolated cache/output directories are explicitly assigned.
- Read-only comparisons of already-produced evidence are safe, but do not run multiple concurrent validators that mutate the same repo checkout or shared Zig cache.
