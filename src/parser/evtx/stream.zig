//! Streaming record iterator for EVTX parsing.

const std = @import("std");
const binxml = @import("../binxml/mod.zig");
const format = @import("format.zig");
const logger = @import("../../logger.zig");
const output = @import("output.zig");

pub const FileHeader = format.FileHeader;
pub const Chunk = format.Chunk;
pub const EventRecordView = format.EventRecordView;
pub const RecordIterator = format.RecordIterator;
pub const OutputWriter = output.OutputWriter;

/// Output format mode for streaming.
pub const OutputMode = enum { xml, json_lines };

pub const ReadFn = *const fn (*anyopaque, []u8) anyerror!void;

/// Streaming record iterator that reads strictly sequentially from a caller-provided reader.
/// The reader must implement `readNoEof([]u8) !void`. No seeks are performed.
pub const RecordStream = struct {
    allocator: std.mem.Allocator,
    opts: ParserOptions,

    // Source vtable: opaque context and a read callback matching std.io.Reader.readNoEof
    read_ctx: *anyopaque,
    read_fn: ReadFn,

    // Format state
    mode: OutputMode,
    out: OutputWriter,

    // Parse state
    hdr: FileHeader,
    chunk_index: usize = 0,
    ctx: binxml.Context,
    have_iter: bool = false,
    current_chunk: Chunk = undefined,
    rec_iter: RecordIterator = undefined,
    selected_including_skips: usize = 0,
    emitted: usize = 0,

    /// Adapter to satisfy `reader.interface.streamExact` for FileHeader/Chunk readers.
    pub fn readNoEof(self: *RecordStream, buf: []u8) !void {
        return self.read_fn(self.read_ctx, buf);
    }

    /// Initialize a streaming iterator from an abstract reader.
    pub fn init(allocator: std.mem.Allocator, read_ctx: *anyopaque, read_fn: ReadFn, opts: ParserOptions, fmt: []const u8) !RecordStream {
        const mode: OutputMode = if (std.mem.eql(u8, fmt, "xml")) .xml else .json_lines;
        var tmp = RecordStream{
            .allocator = allocator,
            .opts = opts,
            .read_ctx = read_ctx,
            .read_fn = read_fn,
            .mode = mode,
            .out = OutputWriter.initSerializeOnly(if (mode == .xml) .xml else .json_lines),
            .hdr = undefined,
            .ctx = try binxml.Context.init(allocator),
        };

        // Read and validate header sequentially from the same reader
        tmp.hdr = try FileHeader.read(&tmp);
        if (opts.validate_checksums) try tmp.hdr.validateChecksum();
        return tmp;
    }

    pub fn deinit(self: *RecordStream) void {
        self.out.deinit();
        self.ctx.deinit();
    }

    fn ensureIterator(self: *RecordStream) !bool {
        if (self.have_iter) return true;
        if (self.chunk_index >= self.hdr.core.num_chunks) return false;

        // Strictly sequential: read next chunk from the same reader
        self.current_chunk = try Chunk.read(self);
        if (self.opts.validate_checksums) try self.current_chunk.validateChecksums();
        // Prepare per-chunk context and iterator
        self.ctx.resetPerChunk();
        // Pre-cache common strings from chunk header for faster lookups
        self.ctx.preCacheFromChunkHeader(&self.current_chunk.buf, &self.current_chunk.header.common_string_offsets);
        if (self.opts.verbosity >= 3) logger.setModuleLevel("binxml", .trace);
        self.rec_iter = self.current_chunk.records();
        self.have_iter = true;
        return true;
    }

    /// Returns a slice valid until the next call. Caller should copy if needed.
    pub fn nextSerialized(self: *RecordStream) !?[]const u8 {
        while (true) {
            if (!try self.ensureIterator()) return null;
            if (try self.rec_iter.next()) |rec| {
                if (self.opts.skip_first > 0 and self.selected_including_skips < self.opts.skip_first) {
                    self.selected_including_skips += 1;
                    continue;
                }
                self.selected_including_skips += 1;
                const view = EventRecordView{ .id = rec.identifier, .timestamp_filetime = rec.written_time, .raw_xml = rec.binxml, .chunk_buf = rec.chunk_buf };
                const bytes = try self.out.serializeRecord(view, &self.ctx);
                self.emitted += 1;
                if (self.opts.max_records != 0 and self.emitted >= self.opts.max_records) {
                    // Mark exhausted so subsequent calls return null
                    self.chunk_index = self.hdr.core.num_chunks;
                }
                return bytes;
            } else {
                // End of chunk
                self.have_iter = false;
                self.chunk_index += 1;
                continue;
            }
        }
    }
};

/// Parser options (re-exported from parser.zig for convenience).
pub const ParserOptions = struct {
    validate_checksums: bool = true,
    verbosity: u8 = 0,
    max_records: usize = 0,
    skip_first: usize = 0,
};
