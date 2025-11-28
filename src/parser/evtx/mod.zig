//! Public facade for the EVTX parser module.
//!
//! Main entry points:
//! - `EvtxParser` for sequential and concurrent parsing
//! - `RecordStream` for streaming record iteration
//! - `Output` for configuring output format (XML/JSON)

pub const ParserOptions = @import("parser.zig").ParserOptions;
pub const EvtxParser = @import("parser.zig").EvtxParser;

pub const OutputWriter = @import("output.zig").OutputWriter;
pub const JsonMode = @import("output.zig").JsonMode;

pub const RecordStream = @import("stream.zig").RecordStream;
pub const OutputMode = @import("stream.zig").OutputMode;

pub const EventRecordView = @import("format.zig").EventRecordView;

