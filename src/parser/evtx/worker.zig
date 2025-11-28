//! Concurrent EVTX parsing with worker threads.

const std = @import("std");
const binxml = @import("../binxml/mod.zig");
const alloc_mod = @import("alloc");
const logger = @import("../../logger.zig");
const log = logger.scoped("evtx");

const format = @import("format.zig");
const output = @import("output.zig");

pub const FileHeader = format.FileHeader;
pub const Chunk = format.Chunk;
pub const EventRecordView = format.EventRecordView;
pub const Output = output.Output;

pub const OutKind = enum { xml, json_single, json_lines };

pub const WorkItem = struct {
    index: usize,
    chunk: Chunk,
};

pub const WorkQueue = struct {
    mutex: std.Thread.Mutex = .{},
    not_empty: std.Thread.Condition = .{},
    not_full: std.Thread.Condition = .{},
    buf: []WorkItem,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,
    closed: bool = false,

    pub fn init(alloc: std.mem.Allocator, capacity: usize) !WorkQueue {
        const arr = try alloc.alloc(WorkItem, capacity);
        return .{ .buf = arr };
    }

    pub fn deinit(self: *WorkQueue, alloc: std.mem.Allocator) void {
        alloc.free(self.buf);
    }

    pub fn push(self: *WorkQueue, item: WorkItem) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.count == self.buf.len and !self.closed) self.not_full.wait(&self.mutex);
        if (self.closed) return; // drop silently if closed
        self.buf[self.tail] = item;
        self.tail = (self.tail + 1) % self.buf.len;
        self.count += 1;
        self.not_empty.signal();
    }

    pub fn close(self: *WorkQueue) void {
        self.mutex.lock();
        self.closed = true;
        self.mutex.unlock();
        self.not_empty.broadcast();
        self.not_full.broadcast();
    }

    pub fn pop(self: *WorkQueue) ?WorkItem {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.count == 0) {
            if (self.closed) return null;
            self.not_empty.wait(&self.mutex);
        }
        const item = self.buf[self.head];
        self.head = (self.head + 1) % self.buf.len;
        self.count -= 1;
        self.not_full.signal();
        return item;
    }
};

pub const ParserOptions = struct {
    validate_checksums: bool = true,
    verbosity: u8 = 0,
    max_records: usize = 0,
    skip_first: usize = 0,
};

pub const Worker = struct {
    allocator: std.mem.Allocator,
    opts: ParserOptions,
    out_kind: OutKind,
    queue: *WorkQueue,
    stdout_writer: std.fs.File.Writer,
    write_mutex: *std.Thread.Mutex,
    emitted: *usize,
    skipped: *usize,

    pub fn run(self: *Worker) void {
        // Per-thread output and context
        var out = switch (self.out_kind) {
            .xml => Output.xml(self.stdout_writer),
            .json_single => Output.json(self.stdout_writer, .single),
            .json_lines => Output.json(self.stdout_writer, .lines),
        };
        var ctx = binxml.Context.init(self.allocator) catch return;
        defer ctx.deinit();
        while (true) {
            const opt_item = self.queue.pop();
            if (opt_item == null) break;
            var item = opt_item.?;
            // Per-chunk parse
            if (self.opts.verbosity >= 1) log.info("chunk {d}: free_off=0x{x}, last_rec_off=0x{x}", .{ item.index, item.chunk.header.free_space_offset, item.chunk.header.last_event_record_offset });
            if (self.opts.validate_checksums) {
                if (item.chunk.validateChecksums()) |_| {} else |e| {
                    log.err("chunk {d} checksum error: {s}", .{ item.index, @errorName(e) });
                    continue;
                }
            }
            ctx.resetPerChunk();
            // Pre-cache common strings from chunk header for faster lookups
            ctx.preCacheFromChunkHeader(&item.chunk.buf, &item.chunk.header.common_string_offsets);
            ctx.verbose = (self.opts.verbosity >= 3);
            out.setContext(&ctx);
            var rec_iter = item.chunk.records();
            const has_limits = (self.opts.max_records != 0) or (self.opts.skip_first > 0);
            if (!has_limits) {
                // Fast path: no global limits, render the whole chunk to a local buffer, then single write
                var chunk_out = std.ArrayList(u8).initCapacity(alloc_mod.get(), 0) catch return;
                defer chunk_out.deinit(alloc_mod.get());
                _ = chunk_out.ensureTotalCapacityPrecise(alloc_mod.get(), 96 * 1024) catch {};
                while (rec_iter.next() catch null) |rec| {
                    if (self.opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
                    const view = EventRecordView{ .id = rec.identifier, .timestamp_filetime = rec.written_time, .raw_xml = rec.binxml, .chunk_buf = rec.chunk_buf };
                    const bytes = out.serializeRecord(view) catch |e| {
                        log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                        continue;
                    };
                    chunk_out.appendSlice(alloc_mod.get(), bytes) catch {
                        continue;
                    };
                }
                self.write_mutex.lock();
                _ = self.stdout_writer.interface.writeAll(chunk_out.items) catch {};
                self.write_mutex.unlock();
            } else {
                var selected_including_skips: usize = 0;
                while (rec_iter.next() catch null) |rec| {
                    if (self.opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
                    if (self.opts.skip_first > 0) {
                        self.write_mutex.lock();
                        const should_skip = (self.skipped.* < self.opts.skip_first);
                        if (should_skip) self.skipped.* += 1;
                        self.write_mutex.unlock();
                        if (should_skip) continue;
                    }
                    selected_including_skips += 1;
                    const view = EventRecordView{ .id = rec.identifier, .timestamp_filetime = rec.written_time, .raw_xml = rec.binxml, .chunk_buf = rec.chunk_buf };
                    const bytes2 = out.serializeRecord(view) catch |e| {
                        log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                        continue;
                    };
                    self.write_mutex.lock();
                    defer self.write_mutex.unlock();
                    if (self.opts.max_records != 0 and self.emitted.* >= self.opts.max_records) {
                        continue;
                    }
                    _ = self.stdout_writer.interface.writeAll(bytes2) catch {
                        continue;
                    };
                    if (self.opts.max_records != 0) {
                        self.emitted.* += 1;
                    }
                }
            }
        }

        // Ensure any buffered stdout data for this worker is flushed
        self.write_mutex.lock();
        _ = self.stdout_writer.interface.flush() catch {};
        self.write_mutex.unlock();
    }
};

/// Run concurrent parsing with worker threads.
pub fn parseConcurrent(
    allocator: std.mem.Allocator,
    reader: anytype,
    opts: ParserOptions,
    out_kind: OutKind,
    num_threads: usize,
) !void {
    // Logging levels
    switch (opts.verbosity) {
        0 => {},
        1 => {
            logger.setModuleLevel("evtx", .info);
            logger.setModuleLevel("binxml", .warn);
            log.info("reading file header...", .{});
        },
        2 => {
            logger.setModuleLevel("evtx", .debug);
            logger.setModuleLevel("binxml", .debug);
            log.info("reading file header...", .{});
        },
        else => {
            logger.setModuleLevel("evtx", .trace);
            logger.setModuleLevel("binxml", .trace);
            log.info("reading file header...", .{});
        },
    }

    var hdr: FileHeader = try FileHeader.read(reader);
    if (opts.validate_checksums) try hdr.validateChecksum();

    // Bounded queue, modest multiple of threads to limit memory
    const q_cap: usize = @max(num_threads * 2, 4);
    var queue = try WorkQueue.init(allocator, q_cap);
    defer queue.deinit(allocator);

    var stdout_file = std.fs.File.stdout();
    var write_buf: [8192]u8 = undefined;
    var write_mutex: std.Thread.Mutex = .{};

    // Shared counters for skip and max limits
    var emitted_count: usize = 0;
    var skipped_count: usize = 0;

    // Spawn workers
    const threads = try allocator.alloc(std.Thread, num_threads);
    defer allocator.free(threads);

    const worker_ctx = try allocator.alloc(Worker, num_threads);
    defer allocator.free(worker_ctx);

    for (worker_ctx, threads) |*ctx, *thread| {
        ctx.* = .{
            .allocator = allocator,
            .opts = opts,
            .out_kind = out_kind,
            .queue = &queue,
            .stdout_writer = stdout_file.writer(&write_buf),
            .write_mutex = &write_mutex,
            .emitted = &emitted_count,
            .skipped = &skipped_count,
        };
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{ctx});
    }

    // Producer: read chunks sequentially and enqueue
    var chunk_index: usize = 0;
    while (chunk_index < hdr.core.num_chunks) : (chunk_index += 1) {
        const chunk = Chunk.read(reader) catch |e| {
            log.err("failed to read chunk {d}: {s}", .{ chunk_index, @errorName(e) });
            break;
        };
        queue.push(.{ .index = chunk_index, .chunk = chunk });
        // Early stop if max_records reached
        if (opts.max_records != 0 and emitted_count >= opts.max_records) break;
    }
    queue.close();

    // Join all worker threads
    for (threads) |thread| thread.join();

    if (opts.verbosity >= 1) log.info("done. emitted~={d}", .{emitted_count});
}
