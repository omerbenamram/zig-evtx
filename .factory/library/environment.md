# Environment

Environment variables, external dependencies, and setup notes.

**What belongs here:** required toolchain paths, optional external tooling, Python/build notes, env-driven runtime behaviors.
**What does NOT belong here:** service ports or command manifests.

---

## Toolchain

- Use Zig 0.16 from `/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig` for mission work and validation.
- Do not rely on PATH `zig` unless it resolves to the same Zig 0.16 binary.
- Repo setup helper `.factory/init.sh` is currently checked in without the executable bit; invoke it as `sh .factory/init.sh` instead of running it directly.

## Python tooling

- Optional Python/build integration uses `uv` and a project-local virtual environment.
- Python validation should only be treated as a required gate if mission work changes Python build/runtime integration files.

## Logging behavior

- CLI/runtime logging can be influenced by environment variables.
- Mission work must preserve env-driven logging semantics when default verbosity is used.
