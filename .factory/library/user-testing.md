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
