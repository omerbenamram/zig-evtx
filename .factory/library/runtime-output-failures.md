## Runtime output failure semantics

- `src/parser/evtx/output.zig` currently converts any destination flush failure
  into `error.WriteFailed` inside `OutputWriter.init`'s adapter.
- That means `error.WriteFailed` is a generic sink write/flush failure in this
  codebase, not a broken-pipe-specific signal.
- CLI entrypoints should only treat `error.WriteFailed` as a clean exit after
  separately confirming the sink is a pipe or socket that was closed by the
  consumer.
