---
name: zig-evtx-worker
description: Implement and verify zig-evtx parser, runtime, and bugfix features on the Zig 0.16 baseline.
---

# Zig Evtx Worker

NOTE: Startup and cleanup are handled by `worker-base`. This skill defines the WORK PROCEDURE.

## When to Use This Skill

Use for implementation features in `zig-evtx`, especially Bugbot fixes, concurrency/runtime behavior, CLI integration, snapshot behavior, and Zig 0.16 tightening work.

## Required Skills

- `zig-abstract-io-migration` when the feature touches explicit `std.Io`, entrypoint ownership, or migration-sensitive runtime boundaries

## Work Procedure

1. Read `CLAUDE.md`, `.factory/library/architecture.md`, `.factory/library/environment.md`, and `.factory/library/user-testing.md`.
2. Identify the exact validation assertions the feature fulfills and restate them in your notes before editing.
3. Add or update failing regression tests first. For Bugbot issues, reproduce the root cause with the narrowest regression possible before implementing the fix.
4. Implement the fix using existing repo patterns unless the feature explicitly requires tightening them toward the Zig 0.16 architecture boundary.
5. Run targeted validation first, then run the repo hard gate `test` command from `.factory/services.yaml`.
6. Run CLI or snapshot smoke checks when the feature affects user-facing runtime behavior.
7. If you touched Python/build integration, run the Python validation path and report it separately.
8. Do not leave background processes running; this repo should validate through bounded shell commands only.

## Example Handoff

```json
{
  "salientSummary": "Fixed the ordered concurrent early-stop regression and the unordered sink-failure cleanup path, then added regression coverage for both. Zig 0.16 tests and CLI smoke passed.",
  "whatWasImplemented": "Updated the concurrency runtime so early sink failure and ordered early return now stop cleanly without deadlock or leaked output ownership. Added targeted regression coverage in the concurrency test surface and verified the CLI still emits expected sample output on Zig 0.16.",
  "whatWasLeftUndone": "",
  "verification": {
    "commandsRun": [
      {
        "command": "\"/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig\" build test -Dtarget=native -Doptimize=Debug -Duse-c-alloc=false",
        "exitCode": 0,
        "observation": "Concurrency regressions and full Zig test graph passed."
      },
      {
        "command": "\"/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig\" build run -- -t 1 -n 1 -o xml samples/system.evtx",
        "exitCode": 0,
        "observation": "CLI emitted the first XML event successfully."
      }
    ],
    "interactiveChecks": [
      {
        "action": "Run CLI sample parse in XML mode",
        "observed": "Valid event output was printed and the process exited cleanly."
      }
    ]
  },
  "tests": {
    "added": [
      {
        "file": "src/test/concurrency_tests.zig",
        "cases": [
          {
            "name": "ordered concurrent early failure drains cleanly",
            "verifies": "ordered mode does not deadlock after early return"
          },
          {
            "name": "unordered sink failure frees/cleans pending output path",
            "verifies": "sink failure stops cleanly and preserves expected failure semantics"
          }
        ]
      }
    ]
  },
  "discoveredIssues": []
}
```

## When to Return to Orchestrator

- A Bugbot issue root cause expands beyond the assigned feature and needs re-slicing
- Validation reveals a dependency/tooling blocker outside the feature scope
- The feature requires a repo-wide architecture pivot rather than a bounded implementation fix
