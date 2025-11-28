//! Public facade for the EVTX parser module.
//!
//! Main entry points:
//! - `EvtxParser` for sequential and concurrent parsing
//! - `RecordStream` for streaming record iteration
//! - `Output` for configuring output format (XML/JSON)

pub const ParserOptions = @import("parser.zig").ParserOptions;
pub const EvtxParser = @import("parser.zig").EvtxParser;

pub const Output = @import("output.zig").Output;
pub const OutputImpl = @import("output.zig").OutputImpl;

pub const RecordStream = @import("stream.zig").RecordStream;
pub const OutputMode = @import("stream.zig").OutputMode;

pub const EventRecordView = @import("format.zig").EventRecordView;

