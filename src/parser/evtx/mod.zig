//! Public facade for the EVTX parser module.
//!
//! Main entry points:
//! - `EvtxParser` for sequential and concurrent parsing
//! - `Output` for configuring output format (XML/JSON)

pub const ParserOptions = @import("parser.zig").ParserOptions;
pub const EvtxParser = @import("parser.zig").EvtxParser;

pub const OutputWriter = @import("output.zig").OutputWriter;
pub const JsonMode = @import("output.zig").JsonMode;
pub const OutputMode = @import("output.zig").OutputMode;
pub const worker = @import("worker.zig");

pub const EventRecordRaw = @import("format.zig").EventRecordRaw;
pub const RecordIterator = @import("format.zig").RecordIterator;
pub const Chunk = @import("format.zig").Chunk;
pub const FileHeader = @import("format.zig").FileHeader;

// Re-export Context for use in snapshot tests and external consumers
pub const Context = @import("../binxml/mod.zig").Context;
