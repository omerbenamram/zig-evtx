## Buffer Optimization Plan and Measurement Protocol

This document tracks buffer-centric optimizations, why they matter, how we will implement them, and their measured impact. For each optimization, we record the benchmark delta and verify that output correctness did not regress.

### Measurement Protocol

- Build mode: production-like ReleaseFast.
- Input file: `samples/security_big_sample.evtx`
- Command under test: `zig-out/bin/evtx_dump_zig --no-checks -o xml samples/security_big_sample.evtx`
- Benchmark tool: `hyperfine`
  - Use at least 10 runs (`-m 10`) and a short warmup (`-w 2`).
  - Clean/rebuild before each optimization measurement.
- Correctness check: ensure record count (JSONL) unchanged.
  - `zig-out/bin/evtx_dump_zig --no-checks -o json samples/security_big_sample.evtx | wc -l` should remain equal to the baseline (currently 62031).
- Optional: generate production flamegraph for qualitative validation: `make flamegraph-prod FLAME_FILE="samples/security_big_sample.evtx" FORMAT=xml DURATION=25`

#### Baseline (pre-optimizations)

- Build: `make clean && make build OPT=ReleaseFast`
- Benchmark: `hyperfine -w 2 -m 10 'zig-out/bin/evtx_dump_zig --no-checks -o xml samples/security_big_sample.evtx'`
- Record count: `zig-out/bin/evtx_dump_zig --no-checks -o json samples/security_big_sample.evtx | wc -l`

Record these here:

- Baseline time (mean ± σ): 1.587 s ± 0.155 s (runs: 10)
- Baseline record count (JSONL): 62031

---

### Opt 1: Reuse per-output scratch buffer and pre-size

- What: Replace per-record `std.ArrayList(u8)` allocations inside `EventRecordView.writeXml`/`writeJson` with a single scratch buffer owned by the output handle. Clear it between records using `clearRetainingCapacity()`. Track previous record size and pre-reserve with slack (e.g., `prev_size * 1.25 + 512`).
- Why hot: In flamegraphs, `_platform_memmove` and `ArrayList.append/ensure/grow` show up due to repeated growth and copies. Reusing and pre-sizing cuts allocs and memmoves.
- Change sketch:
  - Extend `OutputImpl(W)` to hold: `scratch: ArrayList(u8)`, `last_size_hint: usize`.
  - Change `writeRecord` to route rendering into `scratch` via a `writer` and then `w.writeAll(scratch.items)` once.
  - Call `scratch.clearRetainingCapacity()` per record and `scratch.ensureTotalCapacityPrecise(last_size_hint + slack)` before rendering.
- Validation:
  - `make clean && make build OPT=ReleaseFast`
  - `hyperfine -w 2 -m 10 'zig-out/bin/evtx_dump_zig --no-checks -o xml samples/security_big_sample.evtx'`
  - `zig-out/bin/evtx_dump_zig --no-checks -o json samples/security_big_sample.evtx | wc -l` (expect 62031)
- Expected impact: Reduce copies and reallocs; fewer small writes; improved mean runtime.
- Results:
  - Mean ± σ: 1.293 s ± 0.112 s (Δ -18.5% vs baseline)
  - Records (JSONL): 62031 (OK)
  - Notes: Clear reduction in memmove/growth costs; user+sys time both dropped.

### Opt 2: Wrap destination in a buffered writer

- What: Use `std.io.bufferedWriter` around the final destination writer `W` to coalesce many small writes into fewer large ones (64 KiB buffer).
- Why hot: `io.Writer.writeByte/writeAll` appears frequently; buffering reduces syscalls and overhead on pipes/files.
- Change sketch:
  - In `OutputImpl`, construct a buffered writer once (or per `writeRecord` if generic `W` requires), feed it during rendering, then `flush()`.
  - Keep using the scratch `ArrayList(u8)` from Opt 1 or write directly to buffered writer based on mode.
- Validation: same as above.
- Expected impact: Fewer syscalls; modest runtime reduction.
- Results:
  - Mean ± σ: 1.238 s ± 0.020 s (Δ -3.9% vs Opt 1; -22.0% vs baseline)
  - Records (JSONL): 62031 (OK)
  - Notes: Lower variance; fewer syscalls and small writes.

### Opt 3: Reuse `binxml.Context` for rendering

- What: Avoid per-record `binxml.Context.init` inside `EventRecordView.writeXml`/`writeJson`. Instead, pass a reusable context from `EvtxParser` into the renderer, resetting only what’s required per record.
- Why hot: Context creation and its internal allocations show in flamegraphs; reuse amortizes setup and hash-map growth.
- Change sketch:
  - Thread a `*binxml.Context` parameter through `OutputImpl.writeRecord` and renderer calls, or store a pointer in `OutputImpl` set by the parser per chunk.
  - Ensure `Context.resetPerRecord()` is called to avoid cross-record contamination.
- Validation: same as above.
- Expected impact: Fewer allocations and map growth; better cache locality.
- Results:
  - Mean ± σ: 1.606 s ± 0.055 s (Δ +1.2% vs baseline)
  - Records (JSONL): 62031 (OK)
  - Notes: On this workload, context reuse alone didn’t improve the end-to-end runtime (rendering dominates). It should still reduce allocator churn and will complement Opt 1/2/4.

### Opt 4: Arena allocator for ephemeral render temporaries

- What: Replace page allocator usage during render with a per-chunk/per-record `std.heap.ArenaAllocator`. Reset between records.
- Why hot: Many small short-lived allocations contribute to allocator overhead and fragmentation.
- Change sketch:
  - Introduce an arena in `EvtxParser` or `OutputImpl`.
  - Repoint `ArrayList.init` and other temp allocs to the arena allocator. Call `arena.reset()` per record.
- Validation: same as above; watch for peak RSS.
- Expected impact: Lower alloc/free overhead; tighter lifetimes; improved speed.
- Results: time: ... s (Δ ...%), records: ... (OK/FAIL)

### Opt 5: Reduce XML escaping churn

- What: Improve `writeXmlEscaped`/`writeUtf16LeXmlEscaped` to reserve capacity once per input chunk and write directly, reducing repeated `ensureCapacity`/memmove.
- Why hot: Escaping functions show up in leafs; repeated small appends cause growth and copies.
- Change sketch:
  - First pass (cheap) to compute extra space needed (count of escapable chars), then `ensureTotalCapacityPrecise` once, then single-pass write.
  - Alternatively, batch writes of safe spans between escapes.
- Validation: same as above.
- Expected impact: Reduced memmove/copies; modest speedup.
- Results: time: ... s (Δ ...%), records: ... (OK/FAIL)

### Opt 6: IR/output growth strategy and hints

- What: Propagate sizing hints (e.g., previous record serialized size) to pre-size IR/output buffers; avoid default geometric growth in hot loops.
- Why hot: `ArrayList.append/ensure/grow` and `_platform_memmove` are visible in production flamegraphs.
- Change sketch:
  - Track last N record sizes (EMA) and pre-size buffers accordingly.
  - Where possible, estimate output size from input record size as an upper bound.
- Validation: same as above.
- Expected impact: Fewer reallocations; fewer copies; better throughput.
- Results: time: ... s (Δ ...%), records: ... (OK/FAIL)

### Reporting Template (fill per optimization)

```
Opt X: <title>
- Mean ± σ: <new> s ± <σ> s (Δ <percent>%)
- Records (JSONL): <count> (OK/FAIL)
- Notes: <observations>
```


