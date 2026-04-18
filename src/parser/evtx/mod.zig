//! Public facade for the EVTX parser module.
//!
//! Main entry points:
//! - `EvtxParser` for sequential and concurrent parsing
//! - `Serializer` for turning records into XML/JSON bytes
//! - `WriterSink` for the sequential path's `*std.Io.Writer` forwarding

pub const ParserOptions = @import("parser.zig").ParserOptions;
pub const ErrorPolicy = @import("parser.zig").ErrorPolicy;
pub const EvtxParser = @import("parser.zig").EvtxParser;

pub const Serializer = @import("output.zig").Serializer;
pub const WriterSink = @import("output.zig").WriterSink;
pub const OutputMode = @import("output.zig").OutputMode;
pub const worker = @import("worker.zig");

pub const EventRecordRaw = @import("format.zig").EventRecordRaw;
pub const RecordIterator = @import("format.zig").RecordIterator;
pub const Chunk = @import("format.zig").Chunk;
pub const FileHeader = @import("format.zig").FileHeader;

// Re-export Context for use in snapshot tests and external consumers
pub const Context = @import("../binxml/mod.zig").Context;
