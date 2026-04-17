# Native primitives replacement audit and roadmap

## Goal

Create a precise repo-local roadmap for the full effort to replace ad hoc native primitive usage with Zig standard-library or language-native facilities where that reduces maintenance risk, and to explicitly keep custom code where the custom path is justified by format constraints or performance requirements.

This audit focuses on `src/` only. Vendored dependencies in `zig-pkg/` are out of scope.

## Scope and decision rule

A pattern is included here when at least one of these is true:

- it wraps or duplicates a native primitive or std capability
- it depends on builtins or reflection that tend to break across Zig upgrades
- it uses pointer, alignment, vector, or byte reinterpretation primitives
- it exists because std lacks the required primitive and should be explicitly kept

Recommendation categories used below:

- Replace now: move to a std or simpler language primitive in the current codebase
- Replace later: worth replacing, but only after upstream I/O or API migration work
- Keep custom: custom implementation is the right choice, document and test it
- Consolidate: keep the behavior but route all call sites through one helper

## High-level findings

1. The biggest custom-native cluster is UTF-16LE to UTF-8 plus XML and JSON escaping in `src/parser/util_string.zig` and `src/parser/util_simd.zig`.
2. The biggest upgrade-risk cluster is I/O adapter reflection and erased pointer plumbing in `src/parser/evtx/output.zig` and `src/parser/evtx/format.zig`.
3. Binary parsing is already partly consolidated in `src/parser/reader.zig`, but several files still bypass that layer with direct `std.mem.readInt`, `std.mem.bytesToValue`, and raw offset arithmetic.
4. SIMD code is intentionally custom and should stay custom. The roadmap should narrow its public surface and make scalar fallback the normative implementation.
5. Enum reflection over `std.meta.fields(ValueType)` is repeated in several places and should be consolidated behind one helper.

## Dependency order

1. Establish canonical helper layer for binary reads and enum conversion.
2. Normalize reflection-heavy I/O adapters.
3. Consolidate pointer arithmetic helpers for chunk-relative offsets.
4. Decide scalar-first string pipeline boundary.
5. Keep SIMD internals custom, but reduce duplicate escape tables and buffer primitives.
6. Sweep remaining casts, pointer erasure, and builtin callsites.

## Work packages

### WP1. Binary read consolidation

Target:
- `src/parser/reader.zig`
- `src/parser/evtx/format.zig`
- `src/parser/binxml/parser.zig`
- `src/parser/binxml/context.zig`

Outcome:
- one authoritative path for little-endian primitive reads
- one authoritative path for packed-struct decode where layout is stable
- fewer direct `std.mem.readInt` and `std.mem.bytesToValue` callsites outside `reader.zig`

### WP2. I/O adapter and erased-pointer cleanup

Target:
- `src/parser/evtx/output.zig`
- `src/parser/evtx/format.zig`
- entrypoints that construct concrete readers and writers

Outcome:
- isolate reflection on writer and reader shapes
- isolate `@ptrCast` and `@alignCast`
- make later Zig I/O API changes hit one boundary

### WP3. String conversion and escaping boundary cleanup

Target:
- `src/parser/util_string.zig`
- `src/parser/util_simd.zig`
- renderers and value formatting users

Outcome:
- scalar path remains canonical
- SIMD path becomes an implementation detail with shared escape tables and buffer helpers
- explicit reason to keep the fused UTF-16 path custom

### WP4. Enum and type-reflection cleanup

Target:
- `src/parser/binxml/types.zig`
- `src/parser/value_format.zig`
- `src/parser/render_json.zig`

Outcome:
- no repeated `inline for (std.meta.fields(...))` loops for the same conversion
- fewer upgrade-sensitive reflection callsites

### WP5. Pointer arithmetic and chunk-relative offset cleanup

Target:
- `src/parser/binxml/parser.zig`
- `src/bench_serialize.zig`

Outcome:
- raw `@intFromPtr` subtraction replaced by named helpers or retained in one place with tests

## Detailed audit table

| Pattern | Location | Current implementation | Recommendation | Reason / replacement target | Risk | Dependency order | Acceptance checks |
|---|---|---|---|---|---|---|---|
| Unaligned little-endian primitive reads | `src/parser/reader.zig:36,79,82,85,107-109` and downstream users | direct `std.mem.readInt` on byte slices | Consolidate | `reader.readValue`, `reader.readGuid`, `reader.readSystemTime`, `reader.readSid` should be the only public decode surface used outside `reader.zig` | Medium | 1 | `search_files` shows no direct `std.mem.readInt` outside `reader.zig` unless explicitly documented exception |
| Packed struct byte reinterprets for EVTX headers | `src/parser/evtx/format.zig:69-70,137,179` | `std.mem.bytesToValue` on packed structs | Replace now | Route through `value_reader.readValue(T, slice)` to centralize packed decode policy | Low | 1 | file header, chunk header, record iteration tests still pass, and direct `bytesToValue` in `format.zig` is removed |
| Packed struct byte reinterprets for system time | `src/parser/reader.zig:155` | `std.mem.bytesToValue(SystemTime, ...)` | Keep custom, but consolidate | Keep inside `reader.zig` as the authoritative packed decode helper | Low | 1 | no other `SystemTime` decode path exists |
| Generic comptime type dispatch for primitive reads | `src/parser/reader.zig:73-100,217-255` | `@typeInfo`, `@sizeOf`, enum and struct dispatch | Keep custom | This is the canonical binary reader abstraction for EVTX and avoids repeated parsing logic | Medium | 1 | reader unit tests stay green, downstream callsites shrink rather than multiply |
| Repeated enum conversion by reflecting over `ValueType` fields | `src/parser/value_format.zig:214-220,229-231`, `src/parser/render_json.zig:132-138,177-179`, `src/parser/binxml/types.zig:105-109,176-181` | `inline for (std.meta.fields(ValueType))` with `@enumFromInt` | Replace now | Add a single helper like `types.valueTypeFromRaw(raw: u8) ?ValueType` and use it everywhere | Low | 1 | one helper exists, repeated loops disappear, behavior for invalid raw values stays unchanged |
| Array/base-type helper mixin using parent-pointer reflection | `src/parser/binxml/types.zig:153-183` | `@fieldParentPtr("vt", self)` in zero-bit mixin | Keep custom | This gives ergonomic accessors without duplicate storage. Replacing it adds noise and little benefit | Medium | 4 | `ValueTokenHeader.vt` and `SubstitutionHeader.vt` APIs still work, no duplicate raw-type logic introduced |
| Binary layout size override | `src/parser/binxml/types.zig:5-10,145-151` | `binarySize` helper using `@hasDecl(T, "binary_size")` | Keep custom | Needed because `@sizeOf` differs from on-disk layout for `TemplateDefinitionHeader` | Low | 1 | template parsing tests still cover `TemplateDefinitionHeader` spans |
| Fragment-header size computed with `@sizeOf` | `src/parser/binxml/parser.zig:125-126` | `@sizeOf(types.FragmentHeader)` | Replace now | Use `types.binarySize(types.FragmentHeader)` for consistency with binary-layout policy | Low | 1 | fragment-skip logic still works, direct `@sizeOf(types.FragmentHeader)` is gone |
| Descriptor table size computed with `@sizeOf` | `src/parser/binxml/parser.zig:276,292` | `@sizeOf(types.ValueDescriptor)` | Replace now | Use `types.binarySize(types.ValueDescriptor)` even though it currently matches, to keep disk-layout policy consistent | Low | 1 | template value parsing tests still pass |
| Raw pointer subtraction for chunk-relative offsets | `src/parser/binxml/parser.zig:111,191,529`, `src/bench_serialize.zig:95` | `@intFromPtr(a.ptr) - @intFromPtr(b.ptr)` | Replace now | Add helper like `util.sliceOffsetWithin(parent, child) !usize` or local checked helper to make assumptions explicit | Medium | 3 | helper used at all current sites, invariant checked in tests or debug asserts |
| Erased pointer adapter for output destination | `src/parser/evtx/output.zig:60-62,97-112` | `?*anyopaque`, `@ptrCast`, `@alignCast`, stored function pointers | Replace later | Keep temporary until broader I/O migration, then replace with narrower adapter abstraction or generic wrapper at init boundary | High | 2 | all pointer casts are isolated inside one adapter module or helper block, no spread to renderers |
| Writer-shape reflection | `src/parser/evtx/output.zig:40-52,87-95` | `@hasField`, `@typeInfo` to handle `.writer` and `.interface` | Replace later | This is tightly coupled to current std I/O shapes. Defer until I/O migration task, then collapse to one supported writer form | High | 2 | only one file contains writer-shape reflection |
| Reader-shape reflection | `src/parser/evtx/format.zig:23-38` | `@typeInfo`, `@hasField`, `@hasDecl` on reader input | Replace later | Same reason as writer reflection. Replace with one reader capability boundary after I/O migration | High | 2 | `readAll` accepts one stable reader form, compatibility shims moved to one place or removed |
| SIMD vector classification | `src/parser/util_simd.zig:44-205` | `@Vector`, `@splat`, `@bitCast` masks, custom classifier structs | Keep custom | std has no EVTX-specific UTF-16 classify-and-emit primitive. This is performance-sensitive and format-aware | Medium | 5 | scalar and simd outputs match on existing tests and benchmarks |
| SIMD lane block loads and reinterpretation | `src/parser/util_simd.zig:371-372,490-491` | `@memcpy` into `[16]u8`, then `@bitCast` to vector | Keep custom | Safe way to handle potentially unaligned UTF-16LE data before vector reinterpretation | Medium | 5 | no direct alignment casts introduced, simd tests remain equal to scalar |
| Fused UTF-16LE to UTF-8 plus XML escaping | `src/parser/util_string.zig:195-268` | custom scalar pipeline using `std.unicode.Wtf16LeIterator`, `std.unicode.utf8Encode`, custom `xmlEscape` | Keep custom | std lacks XML escaping and std JSON escaping expects UTF-8 input. Fused path avoids an intermediate buffer | Low | 4 | XML rendering snapshots remain unchanged, unit tests cover ASCII, non-ASCII, surrogate, and escaping cases |
| Fused UTF-16LE to UTF-8 plus JSON escaping | `src/parser/util_string.zig:195-268`, mode `.json`; `src/parser/util_simd.zig:479-574` | custom fused conversion and escaping | Keep custom | Same reason as XML path, plus EVTX source strings arrive as unaligned UTF-16LE bytes | Low | 4 | JSON snapshots remain unchanged, scalar and SIMD equality tests pass |
| Duplicate XML escape tables | `src/parser/util_string.zig:271-280`, `src/parser/util_simd.zig:261-269` | separate `xmlEscape` and `xmlEntity` helpers with same mapping | Replace now | Consolidate into one shared escape lookup helper exposed from `util_string` or a tiny shared submodule | Low | 4 | one XML escape table remains, outputs stay identical |
| Duplicate JSON escape tables | `src/parser/util_string.zig:283-294`, `src/parser/util_simd.zig:273-284` | separate `jsonEscape` helpers with same mapping | Replace now | Consolidate into one shared helper | Low | 4 | one JSON escape table remains |
| Custom ASCII fast path for UTF-16LE | `src/parser/util_string.zig:155-182,317-338` | hand-rolled ASCII scan and copy for unaligned UTF-16LE bytes | Keep custom | EVTX strings are mostly ASCII and unaligned. This fast path is format-specific and already shared within scalar code | Low | 4 | performance bench remains within expected range, conversion tests still pass |
| Custom output buffer for SIMD writer | `src/parser/util_simd.zig:303-344` | private `OutputBuffer` with `@memcpy`, `flush`, and room checks | Keep custom, but consolidate | Buffering policy is fine, but helper names and escape helpers should align with scalar module conventions | Low | 5 | no behavior change, fewer duplicated helpers between scalar and simd code |
| Manual UTF-8 encoding for CP-1252 escape path | `src/parser/util_string.zig:384-400` | `cp1252ToCodepoint` + `std.unicode.utf8Encode` + XML byte escape loop | Keep custom | std does not expose a CP-1252 EVTX-specific escaped writer. This is a small, clear custom shim | Low | 4 | ANSI string snapshot tests still pass |
| Manual FILETIME to UTC date decomposition | `src/parser/util_datetime.zig:20-72` | Howard Hinnant algorithm with `@divFloor`, manual parts assembly | Keep custom | std does not provide a direct Windows FILETIME to ISO8601 formatter with this exact semantics and precision | Low | 4 | current datetime tests remain green, especially pre-epoch handling and microsecond precision |
| Float bit reinterpretation | `src/parser/reader.zig:80-89` | `std.mem.readInt` then `@bitCast` to `f32` or `f64` | Keep custom | Correct and minimal for LE binary decode. Best kept in `reader.zig` only | Low | 1 | no float decode logic exists elsewhere |
| Chunk/record span counters with atomic primitives | `src/logger.zig:39,56,136,154,213`, `src/parser/evtx/worker.zig:100,111-122,285,287,228,236` | `std.atomic.Value`, enum-to-int casts, cmpxchg loops | Keep custom | Concurrency bookkeeping is naturally primitive-level and already uses std wrappers rather than raw atomics | Medium | 2 | concurrency tests still pass |
| Enum storage in atomics via `@intFromEnum` and `@enumFromInt` | `src/logger.zig:39,56,136,154,213` | atomic stores/loads on `u8` | Keep custom, but document | std atomic enum ergonomics are limited. Current pattern is explicit and small | Low | 2 | logger behavior unchanged |
| Alignment and pointer casts for Python state storage | `src/evtx_pydust_impl.zig:148` | `@ptrCast(@alignCast(storage))` | Keep custom | FFI boundary needs raw storage reinterpretation. Encapsulate and keep heavily tested | Medium | 2 | Python binding still initializes and iterates correctly |
| Alignment and pointer casts for output context | `src/parser/evtx/output.zig:99,104,110` | `@ptrCast(@alignCast(ctx))` | Replace later | Same cluster as output erased-pointer adapter | High | 2 | no pointer casts leak outside output adapter |
| Manual truncating integer encodes for UTF-8 | `src/parser/util_simd.zig:223-245` | `@truncate` in `encode2Byte`, `encode3Byte`, `encode4Byte` | Keep custom | This is the normal low-level encoding path, small and obvious | Low | 5 | simd encode helpers still match scalar output |
| Misc integer narrowing casts | `src/parser/util_datetime.zig`, `src/parser/binxml/parser.zig`, `src/parser/evtx/worker.zig`, tests | plain `@intCast` | Keep custom, audit opportunistically | These are idiomatic and usually clearer than wrappers. Only wrap where range invariants are repeated | Low | 3 | no new helper churn without repeated invariants |
| Min/max builtins in hot paths | `src/parser/util_string.zig`, `src/parser/util_simd.zig`, `src/parser/evtx/format.zig`, tests | `@min`, `@max` | Keep custom | Language builtins are the native primitive here and already the simplest expression | Low | n/a | no action needed |
| CRC32 checksum implementation selection | `src/parser/evtx/format.zig:4,73-76,96-107` | `std.hash.crc.Crc32` | Keep std | Already uses std primitive, no custom replacement needed | Low | n/a | no action needed |

## Recommended execution sequence

### Phase 1. Remove low-risk duplication

1. Add `types.valueTypeFromRaw` or equivalent helper.
2. Replace repeated `std.meta.fields(ValueType)` loops in:
   - `src/parser/value_format.zig`
   - `src/parser/render_json.zig`
   - `src/parser/binxml/types.zig`
3. Replace `@sizeOf(types.FragmentHeader)` and `@sizeOf(types.ValueDescriptor)` with `types.binarySize(...)`.
4. Consolidate XML and JSON escape lookup helpers used by scalar and SIMD paths.

Why first:
- low behavior risk
- reduces reflection noise before larger I/O and parser changes
- creates reusable helpers for later delegated slices

### Phase 2. Centralize binary decode policy

1. Change EVTX header parsing in `src/parser/evtx/format.zig` to use `value_reader.readValue` for packed structs.
2. Sweep `src/parser/binxml/parser.zig` and `src/parser/binxml/context.zig` for direct primitive reads that can route through `reader.zig` helpers.
3. Keep direct reads only inside `reader.zig` or where a documented span-specific optimization matters.

Why second:
- binary parsing invariants are central to correctness
- keeps future fixes local when Zig changes packed-struct behavior or warnings

### Phase 3. Isolate pointer arithmetic and erased adapters

1. Introduce checked helper for chunk-relative offsets.
2. Replace raw `@intFromPtr` subtraction sites.
3. Keep output adapter casts isolated in `src/parser/evtx/output.zig` until the Zig I/O migration slice lands.
4. Mark `src/parser/evtx/output.zig` and `src/parser/evtx/format.zig` as the only acceptable reflection-heavy I/O boundary files.

Why third:
- high upgrade leverage
- avoids mixing I/O migration with parser semantic work

### Phase 4. Normalize string pipeline boundaries

1. Make `util_string.zig` the authoritative source for escape tables and scalar semantics.
2. Reduce `util_simd.zig` to classification, encode helpers, and output buffering.
3. Keep public APIs stable:
   - `writeUtf16LeXmlEscaped`
   - `writeUtf16LeJsonEscaped`
   - `writeUtf16LeRawToUtf8`
   - `convertUtf16ToUtf8`
4. Document that std unicode facilities are used internally, but the fused writer remains custom by design.

Why fourth:
- preserves performance while reducing duplicate primitive logic
- makes later benchmarking and SIMD tuning safer

### Phase 5. I/O migration cluster

This is the same cluster already identified in `docs/plans/zig-0.16-upgrade.md`.

1. Replace writer-shape reflection in `src/parser/evtx/output.zig` with one stable adapter model.
2. Replace reader-shape reflection in `src/parser/evtx/format.zig` with one stable reader boundary.
3. Revisit whether `anyopaque` destination storage is still needed once abstract I/O is chosen.

Why last:
- this has the broadest blast radius
- it should ride with the Zig version and std I/O migration work

## Pattern-by-pattern acceptance checklist

Use these checks after each slice.

### Binary read consolidation

- `search_files` for `std.mem.readInt` under `src/` shows matches only in `src/parser/reader.zig` or intentionally documented exceptions.
- `search_files` for `std.mem.bytesToValue` under `src/` shows matches only in `src/parser/reader.zig` or intentionally documented exceptions.
- `zig build test` passes.

### Enum reflection cleanup

- `search_files` for `std.meta.fields(ValueType)` under `src/` returns only the helper implementation or zero sites.
- invalid raw value behavior remains unchanged in formatter and renderer paths.

### Pointer arithmetic cleanup

- `search_files` for `@intFromPtr` under `src/` is reduced to helper implementation and any FFI-specific exceptions.
- record and template offset calculations still pass snapshot and nested-template tests.

### String pipeline cleanup

- scalar and SIMD equality tests in `src/parser/util_simd.zig` still pass.
- XML snapshot tests involving escaping, nested BinXML, ANSI strings, and trailing spaces still pass.
- JSON snapshot tests still pass.
- benchmarks still show SIMD path as a win on long ASCII-heavy inputs.

### I/O boundary cleanup

- `search_files` for `@hasField|@hasDecl|\.interface` under `src/` is limited to explicit adapter boundaries.
- `search_files` for `@ptrCast\(@alignCast` under `src/` is limited to FFI or one adapter boundary.
- CLI, snapshot tool, benchmarks, and Python extension still compile.

## Reasons to keep custom code

These areas should stay custom unless Zig stdlib grows a directly matching primitive.

1. UTF-16LE fused conversion plus XML escaping.
   - std has unicode iteration and UTF-8 encode helpers.
   - std does not provide EVTX-ready UTF-16LE to XML-escaped writer over unaligned bytes.

2. UTF-16LE fused conversion plus JSON escaping.
   - std JSON escaping assumes UTF-8 input.
   - EVTX source data is UTF-16LE and often unaligned.

3. SIMD classify-and-emit path.
   - This is domain-specific optimization code with scalar parity tests already present.

4. FILETIME and SYSTEMTIME formatting behavior.
   - The code needs exact EVTX-compatible formatting semantics, including microsecond formatting and the current pre-epoch clamp.

5. Binary-size override for structs whose in-memory layout differs from on-disk layout.
   - That is a real file-format constraint, not accidental complexity.

## Open issues and watch-outs

1. `convertUtf16ToUtf8` uses a fixed stack buffer of 512 bytes in `src/parser/util_string.zig`. If long names ever appear beyond that assumed bound, the replacement effort should include either an overflow check or a spill path. This is adjacent to native-primitives cleanup because a more centralized helper makes that bug easier to fix safely.
2. `src/parser/evtx/output.zig` is currently the highest-risk area for Zig API churn because it combines reflection, erased pointers, and std I/O shape assumptions.
3. `src/parser/evtx/format.zig` and `src/parser/reader.zig` should stay aligned on packed-struct decode policy. Splitting them further will recreate the same portability risk this roadmap is trying to reduce.
4. `src/evtx_pydust_impl.zig` needs special treatment because FFI storage casting is legitimate. Do not over-generalize those casts into normal parser code.

## Suggested delegated-slice map

If this work is split across future tasks, use these slice boundaries.

1. Slice A: add `ValueType` raw conversion helper and remove repeated reflection loops.
2. Slice B: convert `evtx/format.zig` packed header reads to the reader helper layer.
3. Slice C: add checked slice-offset helper and replace raw `@intFromPtr` subtraction sites.
4. Slice D: consolidate XML and JSON escape lookup helpers across scalar and SIMD modules.
5. Slice E: isolate all remaining writer and reader reflection behind one adapter boundary.
6. Slice F: review fixed-size stack buffers in conversion helpers and add explicit bounds strategy.

## Completion bar for the full effort

The native-primitives replacement effort is complete when all of these are true:

- custom code remains only where it carries format-specific or performance-specific value
- reflection-heavy and cast-heavy upgrade seams are isolated to narrow adapter boundaries
- binary decode policy is centralized in `reader.zig` and `binxml/types.zig`
- duplicated primitive helpers across scalar and SIMD string modules are removed
- all current tests pass, including unit, snapshot, and concurrency suites
- benchmark-only code still builds or is intentionally gated with documented rationale
