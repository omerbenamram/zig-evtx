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

