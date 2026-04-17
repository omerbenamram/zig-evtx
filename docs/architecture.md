# EVTX Parser Architecture

This document describes the architecture of the Zig EVTX parser, focusing on the
Binary XML (BinXML) parsing and template instantiation system.

## Overview

The parser uses a **two-stage architecture** with type-safe template caching:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           EVTX FILE                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                                     │
│  │  Chunk   │ │  Chunk   │ │  Chunk   │  ...                                │
│  │  64 KB   │ │  64 KB   │ │  64 KB   │                                     │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘                                     │
│       │            │            │                                           │
└───────┼────────────┼────────────┼───────────────────────────────────────────┘
        │            │            │
        ▼            ▼            ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                      STAGE 1: PARSE TO IR                                 │
│                                                                           │
│   ┌─────────────────────────────────────────────────────────────────────┐ │
│   │                    Per-Chunk Context                                │ │
│   │  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────┐ │ │
│   │  │  Template Cache  │  │   Name Cache     │  │   Arena Allocator  │ │ │
│   │  │  DefKey→Template │  │  offset→Name     │  │   (reset/chunk)    │ │ │
│   │  └────────┬─────────┘  └──────────────────┘  └────────────────────┘ │ │
│   │           │                                                         │ │
│   └───────────┼─────────────────────────────────────────────────────────┘ │
│               │                                                           │
│               ▼                                                           │
│   ┌─────────────────────────────────────────────────────────────────────┐ │
│   │              Template (cached, may contain Placeholder)             │ │
│   │  ┌──────────────────────────────────────────────────────────────┐   │ │
│   │  │  Element "Event"                                              │   │ │
│   │  │    ├── Element "System"                                       │   │ │
│   │  │    │     ├── Attr: Name                                       │   │ │
│   │  │    │     ├── PLACEHOLDER(id=0, vtype=0x01)  ← substitution   │   │ │
│   │  │    │     └── PLACEHOLDER(id=1, vtype=0x08)                   │   │ │
│   │  │    └── Element "EventData"                                    │   │ │
│   │  │          └── PLACEHOLDER(id=2, vtype=0x21)  ← nested BinXML  │   │ │
│   │  └──────────────────────────────────────────────────────────────┘   │ │
│   └─────────────────────────────────────────────────────────────────────┘ │
│               │                                                           │
│               │  .instantiate(values, chunk, ctx)                         │
│               ▼                                                           │
│   ┌─────────────────────────────────────────────────────────────────────┐ │
│   │            ElementTree (resolved, no Placeholder nodes)             │ │
│   │  ┌──────────────────────────────────────────────────────────────┐   │ │
│   │  │  Element "Event"                                              │   │ │
│   │  │    ├── Element "System"                                       │   │ │
│   │  │    │     ├── Attr: Name                                       │   │ │
│   │  │    │     ├── Text "UserLogon"           ← resolved string    │   │ │
│   │  │    │     └── Value(0x08, bytes)         ← resolved value     │   │ │
│   │  │    └── Element "EventData"                                    │   │ │
│   │  │          └── Element "Data" (nested)    ← parsed & spliced   │   │ │
│   │  └──────────────────────────────────────────────────────────────┘   │ │
│   └─────────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                      STAGE 2: RENDER                                      │
│                                                                           │
│   ElementTree ──┬──► XML Renderer  ──► <Event>...</Event>                 │
│                 │                                                         │
│                 └──► JSON Renderer ──► {"Event": {...}}                   │
└───────────────────────────────────────────────────────────────────────────┘
```

## Zig 0.16 std.Io architecture boundary

The repository is moving toward the std.Io layering intended by Zig 0.16.
For zig-evtx, that means keeping a hard boundary between a small runtime shell
that owns process I/O and concurrency primitives, and a pure parser and
renderer core that only consumes injected reader and writer capabilities.

### Boundary in one sentence

Initialize `std.Io` once at the executable or tool entrypoint, construct any
runtime-backed stdout or file sink there, and pass only the minimum reader,
writer, and option state down into parsing and rendering code.

### Layering model used by this repo

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     RUNTIME SHELL                                           │
│                                                                             │
│  `src/main.zig`              `src/snapshot_tool.zig`                        │
│  benchmarks / bindings       future embedding adapters                      │
│                                                                             │
│  Owns:                                                                      │
│  - `std.Io` initialization                                                   │
│  - stdout / stderr / file handle construction                               │
│  - thread-count selection and execution mode                                │
│  - top-level cancellation policy                                             │
│  - process-facing broken-pipe handling                                       │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │ injects concrete runtime state
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     ORCHESTRATION LAYER                                     │
│                                                                             │
│  `src/parser/evtx/parser.zig`                                               │
│  `src/parser/evtx/output.zig`                                               │
│  `src/parser/evtx/worker.zig`                                               │
│                                                                             │
│  Owns:                                                                      │
│  - parser options and execution mode                                        │
│  - chunk scheduling and record iteration                                    │
│  - output mode selection                                                    │
│  - ordered vs unordered concurrent drain semantics                          │
│  - propagation of cancellation and fatal write state                        │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │ injects abstract read / write capability
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     PURE CORE                                               │
│                                                                             │
│  BinXML parsing, IR construction, template instantiation, renderers         │
│                                                                             │
│  Owns:                                                                      │
│  - deterministic EVTX and BinXML parsing                                    │
│  - template cache and arena lifetimes                                       │
│  - format rendering logic                                                   │
│                                                                             │
│  Does not own:                                                              │
│  - process stdio                                                            │
│  - global `std.Io` runtime lookup                                           │
│  - thread creation policy                                                   │
│  - shell-level pipe decisions                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why this boundary matters for zig-evtx

- EVTX parsing is deterministic and spec-driven. It benefits from receiving a
  reader and producing records without needing to know where bytes come from or
  where output goes.
- Zig 0.16 std.Io is designed around explicit runtime ownership. The repo gets
  a cleaner migration if runtime-backed handles are created once and then
  threaded downward explicitly.
- Concurrent output is the one place where runtime state, cancellation, and
  shell-visible failure modes meet. That seam belongs in the orchestration
  layer, not inside BinXML parsing or rendering code.

### Intended ownership rules

#### Runtime shell owns std.Io initialization

- `main.zig`, `snapshot_tool.zig`, and other top-level adapters should be the
  only places that initialize the std.Io runtime and derive stdout, stderr,
  file readers, or file writers from it.
- The parser stack should accept injected handles or capabilities.
- Worker code should consume explicitly provided runtime-backed state when
  concurrent writes require it.

#### Pure core owns parsing and serialization logic

- Core parsing code should remain generic over the minimum reader operations it
  needs.
- Rendering code should remain generic over the minimum writer operations it
  needs.
- Scratch buffering should stay local to serialization helpers such as
  `OutputWriter`, because that keeps buffering strategy close to formatting
  logic without leaking runtime construction throughout the repo.

#### Orchestration owns cancellation and emission policy

- `parser.zig` and the concurrent worker path own when to stop after
  `max_records`, how ordered slots drain, and how unordered mode emits records.
- They should propagate cancellation as state passed through worker control
  paths.
- They should not re-derive a global runtime internally.

### Cancellation ownership

Cancellation in zig-evtx should be single-owner and top-down.

- The entrypoint chooses the high-level stop conditions: CLI record limit,
  explicit cancellation, process write failure, or broken pipe.
- The orchestration layer translates those conditions into worker stop signals
  and ordered-drain termination.
- The pure parser core stays cancellation-aware only through return paths and
  bounded work units. It should not own shared cancellation state.

For concurrent execution this implies:

- `max_records` belongs to orchestration, because it is an emission policy.
- broken-pipe and write-failure handling belong at the shell or parser
  boundary, because they are properties of the active sink.
- worker threads should observe one explicit cancellation source rather than
  mix local flags, implicit runtime state, and shell-specific error handling.

### Backend strategy

The repo should support multiple shells around one parser core.

- CLI backend: process stdio, thread count, and shell-visible broken-pipe
  behavior.
- snapshot backend: file-backed readers and writers with deterministic output.
- embedding backends such as Python: adapter-owned buffers or files with the
  same parser and renderer core.

This works best when backends differ only in the runtime shell layer.

Practical rule:

- add backend-specific I/O setup in entrypoints or adapter files
- keep parser, renderer, and template code backend-agnostic
- keep worker runtime needs explicit so tests can inject collection sinks or
  failure behavior without depending on process stdout

### Anti-patterns to avoid during the Zig 0.16 migration

- Initializing or looking up std.Io runtime state deep inside `worker.zig`,
  renderers, or parsing helpers.
- Letting parser internals depend on process stdout or stderr ownership.
- Reintroducing 0.15-style `.interface` probing or multiple reader and writer
  shape fallbacks in core code.
- Creating extra buffering layers whose only job is to count bytes or mimic old
  generic wrappers.
- Encoding broken-pipe behavior directly into pure rendering logic.
- Making concurrency tests rely only on shell pipelines when a controlled sink
  can be injected at the orchestration seam.

### Current repo read, relevant to this boundary

- `src/parser/evtx/output.zig`, `src/main.zig`, and `src/snapshot_tool.zig`
  already reflect part of the intended 0.16 direction.
- `OutputWriter.initSerializeOnly` already keeps scratch buffering local. That
  matches the desired pure-core boundary.
- `src/parser/evtx/worker.zig` is still the hottest integration seam because it
  mixes scheduling, serialization, draining, cancellation, and pipe behavior.
- The active stabilization work should keep owning `worker.zig`. Documentation
  in this file exists to lock the target boundary without changing that code in
  parallel.

### Review checklist for future changes

When touching std.Io-related code, prefer changes that satisfy all of these:

- Entry points initialize runtime-backed I/O exactly once.
- Parser and renderer APIs receive injected capability rather than constructing
  their own shell resources.
- Cancellation has one clear owner and one propagation path.
- Ordered and unordered concurrent output semantics stay in orchestration code.
- Core EVTX and BinXML logic stays deterministic and backend-agnostic.

## Type-Safe Template System

The parser enforces correctness at compile time using wrapper types:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        TYPE SAFETY FLOW                                     │
│                                                                             │
│  ┌───────────────────┐                      ┌───────────────────────────┐  │
│  │     Template      │                      │       ElementTree         │  │
│  │  (may contain     │  ═══════════════►    │  (guaranteed no           │  │
│  │   Placeholder)    │   .instantiate()     │   Placeholder nodes)      │  │
│  └───────────────────┘                      └─────────────┬─────────────┘  │
│         ▲                                                 │                │
│         │                                                 │                │
│  Cached in Context                              Accepted by Renderers      │
│  (per-chunk)                                    (compile-time enforced)    │
│                                                           │                │
│                                                           ▼                │
│                                              ┌───────────────────────────┐ │
│                                              │   Placeholder case is     │ │
│                                              │   `unreachable` in        │ │
│                                              │   render switch           │ │
│                                              └───────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Wrapper Types

| Type | Contains Placeholder? | Purpose |
|------|----------------------|---------|
| `Template` | Yes | Cached template definitions with substitution markers |
| `ElementTree` | No (guaranteed) | Final resolved output for rendering |

### API Flow

```zig
// Parser returns ElementTree (type-safe guarantee)
const tree: ElementTree = try parseRecord(ctx, chunk, bin);

// Renderers accept ElementTree, not raw *IR.Element
try renderXml(tree.element, writer);
try renderJson(tree.element, allocator, writer);
```

## Template Instantiation

When a template instance token is encountered:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TEMPLATE INSTANCE PROCESSING                             │
│                                                                             │
│  TemplateInstance Token                                                     │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  token (1B) │ def_data_off (4B) │ template_id (4B) │ ... │ values... │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│       │                   │                                   │             │
│       │                   │                                   │             │
│       ▼                   ▼                                   ▼             │
│  ┌─────────┐    ┌──────────────────┐             ┌──────────────────────┐   │
│  │ Verify  │    │  Look up cached  │             │  Parse substitution  │   │
│  │  0x0c   │    │    Template      │             │      values          │   │
│  └─────────┘    └────────┬─────────┘             └──────────┬───────────┘   │
│                          │                                  │               │
│                          │     ┌───────────────────────┐    │               │
│                          └────►│ Cache hit? Use cached │◄───┘               │
│                                │ Cache miss? Parse def │                    │
│                                └───────────┬───────────┘                    │
│                                            │                                │
│                                            ▼                                │
│                                ┌───────────────────────┐                    │
│                                │ template.instantiate( │                    │
│                                │   values, chunk, ctx  │                    │
│                                │ )                     │                    │
│                                └───────────┬───────────┘                    │
│                                            │                                │
│                                            ▼                                │
│                                ┌───────────────────────┐                    │
│                                │      ElementTree      │                    │
│                                │  (fully resolved)     │                    │
│                                └───────────────────────┘                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Instantiation: Clone + Resolve

```
Template.instantiate() performs:

1. Clone the cached IR tree structure
2. Walk the clone, resolving Placeholder nodes:

┌─────────────────────────────────────────────────────────────────────────────┐
│  Placeholder                                                                │
│  { id: u16, vtype: u8, optional: bool }                                     │
│                                                                             │
│       │                                                                     │
│       ├── vtype == 0x01 (string)  ──────►  Text { utf16, num_chars }        │
│       │                                                                     │
│       ├── vtype == 0x21 (BinXML)  ──────►  Element (recursive parse)        │
│       │                                    └── May contain template!        │
│       │                                        (recursive instantiation)    │
│       │                                                                     │
│       ├── vtype == 0x81+ (array)  ──────►  [Value, Value, ...]              │
│       │                                    (expanded to multiple nodes)     │
│       │                                                                     │
│       └── other types             ──────►  Value { vtype, bytes }           │
│                                                                             │
│  Optional + empty value  ────────────────►  (skipped entirely)              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## IR Node Types

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           IR.Node Union                                     │
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Element   │  │    Text     │  │    Value    │  │    Placeholder     │ │
│  │  *Element   │  │ utf16,chars │  │ vtype,bytes │  │  id,vtype,optional │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│                                                              ▲              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │              │
│  │   CharRef   │  │  EntityRef  │  │    CData    │    Only in cached      │
│  │    u16      │  │    Name     │  │ utf16,chars │    Template, never     │
│  └─────────────┘  └─────────────┘  └─────────────┘    in ElementTree      │
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                         │
│  │     Pad     │  │  PITarget   │  │   PIData    │                         │
│  │    void     │  │    Name     │  │ utf16,chars │                         │
│  └─────────────┘  └─────────────┘  └─────────────┘                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Performance Characteristics

### Benchmark: Template Caching Approaches

Tested on `samples/security.evtx` (~2300 records):

| Approach | Mean Time | User CPU | Improvement |
|----------|-----------|----------|-------------|
| Re-parse templates each time | 24.3 ms | 11.9 ms | baseline |
| Clone + resolve (current) | 14.8 ms | 10.0 ms | **1.65x faster** |

### Why Clone + Resolve is Fast

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     PERFORMANCE ANALYSIS                                    │
│                                                                             │
│  RE-PARSE APPROACH (old):                                                   │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  For each template instance:                                           │ │
│  │    1. Read template bytes from chunk              O(1)                 │ │
│  │    2. Parse tokens, build IR tree                 O(n) + allocations   │ │
│  │    3. Resolve substitutions inline                O(s)                 │ │
│  │                                                                        │ │
│  │  Total: O((n + s) × instances) with repeated parsing overhead          │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  CLONE + RESOLVE APPROACH (current):                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  First instance of template:                                           │ │
│  │    1. Parse template with Placeholder nodes       O(n) + allocations   │ │
│  │    2. Cache the Template                          O(1)                 │ │
│  │                                                                        │ │
│  │  Subsequent instances:                                                 │ │
│  │    1. Clone cached IR tree                        O(n) memcpy-like     │ │
│  │    2. Resolve Placeholder nodes                   O(p) where p << n    │ │
│  │                                                                        │ │
│  │  Total: O(n) once + O((n + p) × (instances - 1))                       │ │
│  │  Where p = placeholder count, typically 5-20 per template              │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  KEY INSIGHT: Cloning a tree structure is mostly memcpy, which is          │
│  significantly faster than re-parsing bytes with token dispatch.            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Memory Efficiency

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       MEMORY LAYOUT                                         │
│                                                                             │
│  Per-Chunk Arena Allocator:                                                 │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │ │
│  │  │Template │ │Template │ │Template │ │ Cloned  │ │ Cloned  │  ...      │ │
│  │  │   #1    │ │   #2    │ │   #3    │ │ inst A  │ │ inst B  │           │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘           │ │
│  │                                                                        │ │
│  │  At chunk boundary: arena.reset(.retain_capacity)                      │ │
│  │  → All allocations freed atomically, capacity retained                 │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  Template Cache (long-lived):                                               │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  HashMap: DefKey → Template                                            │ │
│  │  ┌──────────────────┐  ┌──────────────────┐                            │ │
│  │  │ DefKey (20 bytes)│  │ Template (8 bytes)│                           │ │
│  │  │  def_off + guid  │  │  root: *Element   │                           │ │
│  │  └──────────────────┘  └──────────────────┘                            │ │
│  │                                                                        │ │
│  │  At chunk boundary: cache.clearRetainingCapacity()                     │ │
│  │  → Entries cleared, hash table capacity retained                       │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## File Structure

```
src/parser/
├── binxml/
│   ├── parser.zig      ← Main BinXML parser, parseRecord(), parseTemplateInstance()
│   ├── context.zig     ← Template/ElementTree types, cache, instantiation
│   ├── common.zig      ← Offset calculations, header skipping
│   ├── tokens.zig      ← Token constants (TOK_TEMPLATE_INSTANCE, etc.)
│   ├── types.zig       ← Binary format structs (headers, descriptors)
│   └── mod.zig         ← Public API facade
├── ir.zig              ← IR types: Node, Element, Attr, Placeholder
├── render_xml.zig      ← XML renderer (accepts ElementTree)
├── render_json.zig     ← JSON renderer (accepts ElementTree)
└── evtx/
    ├── format.zig      ← EVTX file/chunk/record structures
    ├── output.zig      ← OutputWriter for streaming results
    └── parser.zig      ← Top-level EVTX file parser
```

## Invariants

1. **ElementTree has no Placeholder nodes** — enforced by type system
2. **Template is only accessed via .instantiate()** — returns ElementTree
3. **Renderers accept ElementTree** — Placeholder case is `unreachable`
4. **Arena is reset per-chunk** — all IR is freed atomically
5. **Cache is cleared per-chunk** — templates don't cross chunk boundaries
6. **Nested BinXML is recursively parsed** — never stored as raw bytes

## References

- [EVTX Binary XML Format](../Windows%20XML%20Event%20Log%20(EVTX).asciidoc)
- [Data-Oriented Design principles applied](https://www.youtube.com/watch?v=yy8jQgmhbAU)

