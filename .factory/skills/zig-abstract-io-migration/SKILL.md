---
name: zig-abstract-io-migration
description: Migrate Zig code to Zig 0.16 abstract std.Io patterns with explicit runtime-boundary ownership.
---

# Zig Abstract Io Migration

NOTE: Startup and cleanup are handled by `worker-base`. This skill defines the WORK PROCEDURE.

## When to Use This Skill

Use for features that import Zig 0.16 migration knowledge, tighten explicit `std.Io` boundaries, or modernize legacy ambient I/O patterns in this repo.

## Required Skills

None

## Work Procedure

1. Read `.factory/library/architecture.md`, `.factory/library/environment.md`, and `.factory/library/zig-0.16-migration.md` before editing.
2. Write or update regression coverage first when a behavior change is required; make the failure explicit before implementing the fix.
3. Migrate from repo entrypoints downward. Prefer explicit `std.Io` and process-boundary ownership over leaf helpers rediscovering runtime state.
4. Preserve deterministic parsing and no-heuristics rules from `CLAUDE.md`.
5. After each cluster of edits, run the narrowest relevant validation command first, then the repo-level hard gate from `.factory/services.yaml`.
6. For knowledge-import-only or docs-only features, if an unrelated repo hard-gate failure is already tracked by another pending runtime/build feature, report it clearly but do not treat that unrelated blocker as a failure of the knowledge-import feature itself.
7. If the change also affects Python/build integration, run the Python path too and report it explicitly.

## zig-evtx repository notes

- Treat this skill as repo-local guidance; future workers must not rely on hidden Hermes state once these files are committed.
- Keep imported guidance specific to `zig-evtx` runtime seams: CLI startup, snapshot tooling, parser/output ownership, and concurrency cleanup.
- Use the mission Zig 0.16 toolchain explicitly at `/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig` for validation examples and implementation notes.
- When importing or updating knowledge, mirror it into repository-owned surfaces under `.factory/library/` or `docs/` so reviewers can inspect it with ordinary repo reads.

## Example Handoff

```json
{
  "salientSummary": "Imported repo-local Zig 0.16 guidance and migrated the CLI startup boundary to explicit std.Io ownership. Added a regression test proving the new path compiles and runs on Zig 0.16.",
  "whatWasImplemented": "Added repo-local Zig 0.16 migration guidance under .factory and docs, then updated the affected entrypoint/helper chain to use explicit std.Io ownership consistent with the repo architecture notes.",
  "whatWasLeftUndone": "",
  "verification": {
    "commandsRun": [
      {
        "command": "\"/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig\" build test -Dtarget=native -Doptimize=Debug -Duse-c-alloc=false",
        "exitCode": 0,
        "observation": "Zig test graph passed on Zig 0.16."
      }
    ],
    "interactiveChecks": []
  },
  "tests": {
    "added": [
      {
        "file": "src/test/example_regression.zig",
        "cases": [
          {
            "name": "example uses explicit io boundary",
            "verifies": "runtime entrypoint passes explicit Zig 0.16 io/state into the work path"
          }
        ]
      }
    ]
  },
  "discoveredIssues": []
}
```

## When to Return to Orchestrator

- A required Zig 0.16 migration decision changes repo-wide architecture beyond the current feature scope
- A dependency or external build surface blocks migration and cannot be fixed locally
- Python/build integration must change substantially and requires reprioritization
