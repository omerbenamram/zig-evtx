# Python Integration

- The Zig 0.16 Python extension build now uses the vendored Zig source tree under `vendor/ziggy-pydust/src/` instead of importing Zig files from the installed `ziggy-pydust` wheel.
- Keep the Python package install step in `make py-test`; it is still used for packaging/stub tooling, but the compiled Zig module sources are repo-owned so upstream Zig 0.15-era APIs in the wheel no longer block Zig 0.16 builds.
- `src/evtx_pydust_impl.zig` now owns its own `std.Io.Threaded` runtime boundary for file-backed iteration and dump helpers.
- Verified validation path: `make py-test ZIG="/home/omerba/.local/share/mise/installs/zig/0.16.0/bin/zig"`.
