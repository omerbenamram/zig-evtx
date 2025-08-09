const std = @import("std");
const crc32 = std.hash.crc;
const binxml = @import("binxml.zig");
const logger = @import("../logger.zig");
const log = logger.scoped("evtx");

pub const ParserOptions = struct {
    validate_checksums: bool = true,
    // Verbosity levels:
    // 0 = warnings+errors only (default)
    // 1 = info
    // 2 = debug
    // 3+ = trace
    verbosity: u8 = 0,
    // 0 means no limit
    max_records: usize = 0,
    // number of records to skip before emitting any output
    skip_first: usize = 0,
};

pub const Output = struct {
    pub const JsonMode = enum { single, lines };

    pub fn xml(writer: anytype) OutputImpl(@TypeOf(writer)) {
        return OutputImpl(@TypeOf(writer)).initXml(writer);
    }

    pub fn json(writer: anytype, mode: JsonMode) OutputImpl(@TypeOf(writer)) {
        return OutputImpl(@TypeOf(writer)).initJson(writer, mode);
    }
};

pub fn OutputImpl(comptime W: type) type {
    return struct {
        w: W,
        mode: enum { xml, json_single, json_lines },
        scratch: std.ArrayList(u8),
        last_size_hint: usize,
        bufw: std.io.BufferedWriter(1048576, W),
        // Optional reusable rendering context provided by parser (per-chunk)
        ctx: ?*binxml.Context = null,
        // Exponential moving average of previous serialized sizes for pre-sizing
        ema_size: f64 = 0.0,
        ema_alpha: f64 = 0.25,

        pub fn initXml(w: W) @This() {
            return .{ .w = w, .mode = .xml, .scratch = std.ArrayList(u8).init(std.heap.page_allocator), .last_size_hint = 4096, .bufw = std.io.BufferedWriter(1048576, W){ .unbuffered_writer = w } };
        }

        pub fn initJson(w: W, json_mode: Output.JsonMode) @This() {
            return .{ .w = w, .mode = if (json_mode == .single) .json_single else .json_lines, .scratch = std.ArrayList(u8).init(std.heap.page_allocator), .last_size_hint = 4096, .bufw = std.io.BufferedWriter(1048576, W){ .unbuffered_writer = w } };
        }

        pub fn setContext(self: *@This(), c: *binxml.Context) void {
            self.ctx = c;
        }

        fn reserveScratch(self: *@This()) !void {
            // Reserve based on last serialized size (+25%) and EMA of recent sizes.
            const slack: usize = 512;
            const growth: usize = self.last_size_hint / 4; // +25%
            var target: usize = self.last_size_hint + growth + slack;
            if (self.ema_size > 0.0) {
                const ema_scaled: f64 = self.ema_size * 1.10 + 512.0;
                const ema_usize: usize = @intFromFloat(ema_scaled);
                if (ema_usize > target) target = ema_usize;
            }
            const max_cap: usize = 4 * 1024 * 1024; // clamp to 4 MiB retained capacity
            if (target > max_cap) target = max_cap;
            self.scratch.clearRetainingCapacity();
            try self.scratch.ensureTotalCapacityPrecise(target);
        }

        pub fn writeRecord(self: *@This(), record: EventRecordView) !void {
            try self.reserveScratch();
            var bw = self.scratch.writer();
            switch (self.mode) {
                .xml => {
                    if (self.ctx) |ctx| {
                        try binxml.renderWithContext(ctx, record.chunk_buf, record.raw_xml, .xml, bw);
                    } else {
                        var local_ctx = try binxml.Context.init(std.heap.page_allocator);
                        defer local_ctx.deinit();
                        try binxml.renderWithContext(&local_ctx, record.chunk_buf, record.raw_xml, .xml, bw);
                    }
                    try bw.writeByte('\n');
                },
                .json_single => {
                    const body_mode: binxml.RenderMode = .json;
                    try bw.writeAll("{");
                    try bw.print("\"event_record_id\":{d},\"timestamp_filetime\":{d},\"Event\":", .{ record.id, record.timestamp_filetime });
                    if (self.ctx) |ctx| {
                        try binxml.renderWithContext(ctx, record.chunk_buf, record.raw_xml, body_mode, bw);
                    } else {
                        var local_ctx = try binxml.Context.init(std.heap.page_allocator);
                        defer local_ctx.deinit();
                        try binxml.renderWithContext(&local_ctx, record.chunk_buf, record.raw_xml, body_mode, bw);
                    }
                    try bw.writeAll("}\n");
                },
                .json_lines => {
                    const body_mode: binxml.RenderMode = .jsonl;
                    try bw.writeAll("{");
                    try bw.print("\"event_record_id\":{d},\"timestamp_filetime\":{d},\"Event\":", .{ record.id, record.timestamp_filetime });
                    if (self.ctx) |ctx| {
                        try binxml.renderWithContext(ctx, record.chunk_buf, record.raw_xml, body_mode, bw);
                    } else {
                        var local_ctx = try binxml.Context.init(std.heap.page_allocator);
                        defer local_ctx.deinit();
                        try binxml.renderWithContext(&local_ctx, record.chunk_buf, record.raw_xml, body_mode, bw);
                    }
                    try bw.writeAll("}\n");
                },
            }
            // Emit once to the buffered underlying writer and update size hint
            var outw = self.bufw.writer();
            try outw.writeAll(self.scratch.items);
            self.last_size_hint = self.scratch.items.len;
            // Update EMA for future reservations
            const cur_len_f: f64 = @floatFromInt(self.scratch.items.len);
            if (self.ema_size == 0.0) {
                self.ema_size = cur_len_f;
            } else {
                self.ema_size = self.ema_size + self.ema_alpha * (cur_len_f - self.ema_size);
            }
        }

        pub fn serializeRecord(self: *@This(), record: EventRecordView) ![]const u8 {
            try self.reserveScratch();
            var bw = self.scratch.writer();
            switch (self.mode) {
                .xml => {
                    if (self.ctx) |ctx| {
                        try binxml.renderWithContext(ctx, record.chunk_buf, record.raw_xml, .xml, bw);
                    } else {
                        var local_ctx = try binxml.Context.init(std.heap.page_allocator);
                        defer local_ctx.deinit();
                        try binxml.renderWithContext(&local_ctx, record.chunk_buf, record.raw_xml, .xml, bw);
                    }
                    try bw.writeByte('\n');
                },
                .json_single => {
                    const body_mode: binxml.RenderMode = .json;
                    try bw.writeAll("{");
                    try bw.print("\"event_record_id\":{d},\"timestamp_filetime\":{d},\"Event\":", .{ record.id, record.timestamp_filetime });
                    if (self.ctx) |ctx| {
                        try binxml.renderWithContext(ctx, record.chunk_buf, record.raw_xml, body_mode, bw);
                    } else {
                        var local_ctx = try binxml.Context.init(std.heap.page_allocator);
                        defer local_ctx.deinit();
                        try binxml.renderWithContext(&local_ctx, record.chunk_buf, record.raw_xml, body_mode, bw);
                    }
                    try bw.writeAll("}\n");
                },
                .json_lines => {
                    const body_mode: binxml.RenderMode = .jsonl;
                    try bw.writeAll("{");
                    try bw.print("\"event_record_id\":{d},\"timestamp_filetime\":{d},\"Event\":", .{ record.id, record.timestamp_filetime });
                    if (self.ctx) |ctx| {
                        try binxml.renderWithContext(ctx, record.chunk_buf, record.raw_xml, body_mode, bw);
                    } else {
                        var local_ctx = try binxml.Context.init(std.heap.page_allocator);
                        defer local_ctx.deinit();
                        try binxml.renderWithContext(&local_ctx, record.chunk_buf, record.raw_xml, body_mode, bw);
                    }
                    try bw.writeAll("}\n");
                },
            }
            self.last_size_hint = self.scratch.items.len;
            const cur_len_f: f64 = @floatFromInt(self.scratch.items.len);
            if (self.ema_size == 0.0) self.ema_size = cur_len_f else self.ema_size = self.ema_size + self.ema_alpha * (cur_len_f - self.ema_size);
            return self.scratch.items;
        }

        pub fn flush(self: *@This()) void {
            self.bufw.flush() catch {};
        }
    };
}

pub const EvtxParser = struct {
    allocator: std.mem.Allocator,
    opts: ParserOptions,

    pub fn init(allocator: std.mem.Allocator, opts: ParserOptions) !EvtxParser {
        return .{ .allocator = allocator, .opts = opts };
    }

    pub fn deinit(self: *EvtxParser) void {
        _ = self;
    }

    pub fn parse(self: *EvtxParser, reader: anytype, out: anytype) !void {
        // Configure logging levels per verbosity
        switch (self.opts.verbosity) {
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
        if (self.opts.validate_checksums) try hdr.validateChecksum();

        var chunk_index: usize = 0;
        var emitted: usize = 0;
        var skipped: usize = 0;
        var failed: usize = 0;
        var ctx = try binxml.Context.init(self.allocator);
        defer ctx.deinit();
        // We need a mutable output to retain and reuse scratch capacity across records
        var out_mut = out;
        while (chunk_index < hdr.num_chunks) : (chunk_index += 1) {
            var chunk = try Chunk.read(reader);
            if (self.opts.verbosity >= 1) log.info("chunk {d}: free_off=0x{x}, last_rec_off=0x{x}", .{ chunk_index, chunk.header.free_space_offset, chunk.header.last_event_record_offset });
            if (self.opts.validate_checksums) try chunk.validateChecksums();
            ctx.resetPerChunk();
            // Seed arena with a modest capacity based on chunk header guidance
            const est_names = chunk.header.common_strings_count;
            const est_templates = chunk.header.template_ptrs_count;
            const bytes_hint: usize = @min((est_names * 128) + (est_templates * 2048), 64 * 1024);
            if (bytes_hint > 0) {
                _ = ctx.arena.allocator().alloc(u8, bytes_hint) catch {};
            }
            // Only enable deepest renderer-specific traces at -vvv
            ctx.verbose = (self.opts.verbosity >= 3);
            // Provide output with reusable context for this chunk
            if (@hasDecl(@TypeOf(out_mut.*), "setContext")) {
                out_mut.setContext(&ctx);
            }
            var rec_iter = chunk.records();
            var selected_including_skips: usize = 0;
            while (try rec_iter.next()) |rec| {
                if (self.opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
                // Skip initial records if requested
                if (self.opts.skip_first > 0 and skipped < self.opts.skip_first) {
                    skipped += 1;
                    continue;
                }
                selected_including_skips += 1;
                const view = EventRecordView{ .id = rec.identifier, .timestamp_filetime = rec.written_time, .raw_xml = rec.binxml, .chunk_buf = rec.chunk_buf };
                out_mut.writeRecord(view) catch |e| {
                    failed += 1;
                    log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                    // If isolating with skip_first, respect -n even when the selected record fails
                    if (self.opts.max_records != 0 and self.opts.skip_first > 0 and selected_including_skips >= self.opts.max_records) {
                        return;
                    }
                    continue; // keep going to inspect later records and compare outputs
                };
                emitted += 1;
                if (self.opts.max_records != 0) {
                    if (self.opts.skip_first > 0) {
                        if (selected_including_skips >= self.opts.max_records) return;
                    } else {
                        if (emitted >= self.opts.max_records) return;
                    }
                }
            }
        }
        if (self.opts.verbosity >= 1) log.info("done. emitted={d} failed={d}", .{ emitted, failed });
    }

    // Concurrent parsing entry point: read chunks sequentially, parse in a thread pool, and stream outputs to stdout
    pub const OutKind = enum { xml, json_single, json_lines };

    const WorkItem = struct {
        index: usize,
        chunk: Chunk,
    };

    const WorkQueue = struct {
        mutex: std.Thread.Mutex = .{},
        not_empty: std.Thread.Condition = .{},
        not_full: std.Thread.Condition = .{},
        buf: []WorkItem,
        head: usize = 0,
        tail: usize = 0,
        count: usize = 0,
        closed: bool = false,

        fn init(alloc: std.mem.Allocator, capacity: usize) !WorkQueue {
            const arr = try alloc.alloc(WorkItem, capacity);
            return .{ .buf = arr };
        }

        fn deinit(self: *WorkQueue, alloc: std.mem.Allocator) void {
            alloc.free(self.buf);
        }

        fn push(self: *WorkQueue, item: WorkItem) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            while (self.count == self.buf.len and !self.closed) self.not_full.wait(&self.mutex);
            if (self.closed) return; // drop silently if closed
            self.buf[self.tail] = item;
            self.tail = (self.tail + 1) % self.buf.len;
            self.count += 1;
            self.not_empty.signal();
        }

        fn close(self: *WorkQueue) void {
            self.mutex.lock();
            self.closed = true;
            self.mutex.unlock();
            self.not_empty.broadcast();
            self.not_full.broadcast();
        }

        fn pop(self: *WorkQueue) ?WorkItem {
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

    pub fn parseConcurrent(self: *EvtxParser, reader: anytype, out_kind: OutKind, num_threads: usize) !void {
        // Logging levels as in sequential parse
        switch (self.opts.verbosity) {
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
        if (self.opts.validate_checksums) try hdr.validateChecksum();

        // Bounded queue, modest multiple of threads to limit memory
        const q_cap: usize = @max(num_threads * 2, 4);
        var queue = try WorkQueue.init(self.allocator, q_cap);
        defer queue.deinit(self.allocator);

        var stdout_file = std.io.getStdOut();
        var write_mutex: std.Thread.Mutex = .{};

        // Shared counters for skip and max limits
        var emitted_count: usize = 0;
        var skipped_count: usize = 0;

        // Worker function
        const Worker = struct {
            parser: *EvtxParser,
            out_kind: OutKind,
            queue: *WorkQueue,
            stdout_writer: @TypeOf(stdout_file.writer()),
            write_mutex: *std.Thread.Mutex,
            emitted: *usize,
            skipped: *usize,

            fn run(self_: *@This()) void {
                // Per-thread output and context
                var output = switch (self_.out_kind) {
                    .xml => Output.xml(self_.stdout_writer),
                    .json_single => Output.json(self_.stdout_writer, .single),
                    .json_lines => Output.json(self_.stdout_writer, .lines),
                };
                var ctx = binxml.Context.init(self_.parser.allocator) catch return;
                defer ctx.deinit();
                var emitting: bool = true;
                while (true) {
                    const opt_item = self_.queue.pop();
                    if (opt_item == null) break;
                    var item = opt_item.?;
                    // Per-chunk parse
                    if (self_.parser.opts.verbosity >= 1) log.info("chunk {d}: free_off=0x{x}, last_rec_off=0x{x}", .{ item.index, item.chunk.header.free_space_offset, item.chunk.header.last_event_record_offset });
                    if (self_.parser.opts.validate_checksums) {
                        if (item.chunk.validateChecksums()) |_| {} else |e| {
                            log.err("chunk {d} checksum error: {s}", .{ item.index, @errorName(e) });
                            continue;
                        }
                    }
                    ctx.resetPerChunk();
                    ctx.verbose = (self_.parser.opts.verbosity >= 3);
                    output.setContext(&ctx);
                    var rec_iter = item.chunk.records();
                    const has_limits = (self_.parser.opts.max_records != 0) or (self_.parser.opts.skip_first > 0);
                    if (!has_limits) {
                        // Fast path: no global limits, render the whole chunk to a local buffer, then single write
                        var chunk_out = std.ArrayList(u8).init(std.heap.page_allocator);
                        defer chunk_out.deinit();
                        _ = chunk_out.ensureTotalCapacityPrecise(96 * 1024) catch {};
                        while (rec_iter.next() catch null) |rec| {
                            if (self_.parser.opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
                            const view = EventRecordView{ .id = rec.identifier, .timestamp_filetime = rec.written_time, .raw_xml = rec.binxml, .chunk_buf = rec.chunk_buf };
                            const bytes = output.serializeRecord(view) catch |e| {
                                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                                continue;
                            };
                            chunk_out.appendSlice(bytes) catch {
                                continue;
                            };
                        }
                        self_.write_mutex.lock();
                        _ = self_.stdout_writer.writeAll(chunk_out.items) catch {};
                        self_.write_mutex.unlock();
                    } else {
                        var selected_including_skips: usize = 0;
                        while (rec_iter.next() catch null) |rec| {
                            if (self_.parser.opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
                            if (self_.parser.opts.skip_first > 0) {
                                self_.write_mutex.lock();
                                const should_skip = (self_.skipped.* < self_.parser.opts.skip_first);
                                if (should_skip) self_.skipped.* += 1;
                                self_.write_mutex.unlock();
                                if (should_skip) continue;
                            }
                            selected_including_skips += 1;
                            const view = EventRecordView{ .id = rec.identifier, .timestamp_filetime = rec.written_time, .raw_xml = rec.binxml, .chunk_buf = rec.chunk_buf };
                            const bytes2 = output.serializeRecord(view) catch |e| {
                                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                                continue;
                            };
                            self_.write_mutex.lock();
                            defer self_.write_mutex.unlock();
                            if (self_.parser.opts.max_records != 0 and self_.emitted.* >= self_.parser.opts.max_records) {
                                emitting = false;
                                continue;
                            }
                            _ = self_.stdout_writer.writeAll(bytes2) catch {
                                continue;
                            };
                            if (self_.parser.opts.max_records != 0) {
                                self_.emitted.* += 1;
                                if (self_.emitted.* >= self_.parser.opts.max_records) emitting = false;
                            }
                        }
                    }
                }
            }
        };

        // Spawn workers
        var threads = try self.allocator.alloc(std.Thread, num_threads);
        defer self.allocator.free(threads);

        var worker_ctx = try self.allocator.alloc(Worker, num_threads);
        defer self.allocator.free(worker_ctx);
        var i: usize = 0;
        while (i < num_threads) : (i += 1) {
            worker_ctx[i] = .{
                .parser = self,
                .out_kind = out_kind,
                .queue = &queue,
                .stdout_writer = stdout_file.writer(),
                .write_mutex = &write_mutex,
                .emitted = &emitted_count,
                .skipped = &skipped_count,
            };
            threads[i] = try std.Thread.spawn(.{}, Worker.run, .{&worker_ctx[i]});
        }

        // Producer: read chunks sequentially and enqueue
        var chunk_index: usize = 0;
        while (chunk_index < hdr.num_chunks) : (chunk_index += 1) {
            const chunk = Chunk.read(reader) catch |e| {
                log.err("failed to read chunk {d}: {s}", .{ chunk_index, @errorName(e) });
                break;
            };
            queue.push(.{ .index = chunk_index, .chunk = chunk });
            // Early stop if max_records reached
            if (self.opts.max_records != 0 and emitted_count >= self.opts.max_records) break;
        }
        queue.close();

        // Join
        i = 0;
        while (i < num_threads) : (i += 1) threads[i].join();

        if (self.opts.verbosity >= 1) log.info("done. emitted~={d}", .{emitted_count});
    }
};

const FileHeader = struct {
    first_chunk: u64,
    last_chunk: u64,
    next_record_id: u64,
    header_size: u32,
    minor: u16,
    major: u16,
    header_block_size: u16,
    num_chunks: u16,
    flags: u32,
    checksum: u32,

    fn read(reader: anytype) !FileHeader {
        var buf: [4096]u8 = undefined;
        try reader.readNoEof(&buf);
        if (!std.mem.eql(u8, buf[0..8], "ElfFile\x00")) return error.BadSignature;
        const first_chunk = std.mem.readInt(u64, buf[8..16], .little);
        const last_chunk = std.mem.readInt(u64, buf[16..24], .little);
        const next_record_id = std.mem.readInt(u64, buf[24..32], .little);
        const header_size = std.mem.readInt(u32, buf[32..36], .little);
        const minor = std.mem.readInt(u16, buf[36..38], .little);
        const major = std.mem.readInt(u16, buf[38..40], .little);
        const header_block_size = std.mem.readInt(u16, buf[40..42], .little);
        const num_chunks = std.mem.readInt(u16, buf[42..44], .little);
        const flags = std.mem.readInt(u32, buf[120..124], .little);
        const checksum = std.mem.readInt(u32, buf[124..128], .little);

        // Verify header CRC32 over first 120 bytes
        var hasher = crc32.Crc32.init();
        hasher.update(buf[0..120]);
        const computed = hasher.final();
        if (computed != checksum) return error.BadHeaderChecksum;
        return .{
            .first_chunk = first_chunk,
            .last_chunk = last_chunk,
            .next_record_id = next_record_id,
            .header_size = header_size,
            .minor = minor,
            .major = major,
            .header_block_size = header_block_size,
            .num_chunks = num_chunks,
            .flags = flags,
            .checksum = checksum,
        };
    }

    fn validateChecksum(self: *const FileHeader) !void {
        _ = self;
    }
};

const Chunk = struct {
    header: ChunkHeader,
    buf: [65536]u8,

    fn read(reader: anytype) !Chunk {
        var buf: [65536]u8 = undefined;
        try reader.readNoEof(&buf);
        const h = try ChunkHeader.parse(&buf);
        return .{ .header = h, .buf = buf };
    }

    fn validateChecksums(self: *const Chunk) !void {
        // Header checksum: CRC32 over bytes 0..120 and 128..512
        const stored_hdr_crc = std.mem.readInt(u32, self.buf[124..128], .little);
        var h = crc32.Crc32.init();
        h.update(self.buf[0..120]);
        h.update(self.buf[128..512]);
        if (h.final() != stored_hdr_crc) return error.BadChunkHeaderChecksum;

        // Events checksum: CRC32 over event records data
        const stored_events_crc = std.mem.readInt(u32, self.buf[52..56], .little);
        var e = crc32.Crc32.init();
        const start: usize = 512;
        const end: usize = @min(self.buf.len, self.header.free_space_offset);
        if (end > start) e.update(self.buf[start..end]);
        if (e.final() != stored_events_crc) return error.BadChunkEventsChecksum;
    }

    fn records(self: *const Chunk) RecordIterator {
        // EVTX chunk header is 512 bytes; event data starts at 512
        return RecordIterator{ .chunk = self, .offset = 512 };
    }
};

const ChunkHeader = struct {
    header_size: u32,
    last_event_record_offset: u32,
    free_space_offset: u32,
    // Parsed guidance from chunk header arrays (relative offsets from chunk start)
    common_string_offsets: [64]u32 = [_]u32{0} ** 64,
    template_ptrs: [32]u32 = [_]u32{0} ** 32,
    common_strings_count: usize = 0,
    template_ptrs_count: usize = 0,

    fn parse(buf: *const [65536]u8) !ChunkHeader {
        if (!std.mem.eql(u8, buf[0..8], "ElfChnk\x00")) return error.BadChunkSignature;
        const header_size = std.mem.readInt(u32, buf[40..44], .little);
        const last_event_record_offset = std.mem.readInt(u32, buf[44..48], .little);
        const free_space_offset = std.mem.readInt(u32, buf[48..52], .little);
        var ch: ChunkHeader = .{ .header_size = header_size, .last_event_record_offset = last_event_record_offset, .free_space_offset = free_space_offset };
        // Common string offset array at 128: 64 u32
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            const off = std.mem.readInt(u32, buf[128 + i * 4 .. 128 + i * 4 + 4][0..4], .little);
            ch.common_string_offsets[i] = off;
            if (off != 0 and off < buf.len) ch.common_strings_count += 1;
        }
        // TemplatePtr array at 384: 32 u32
        i = 0;
        while (i < 32) : (i += 1) {
            const off = std.mem.readInt(u32, buf[384 + i * 4 .. 384 + i * 4 + 4][0..4], .little);
            ch.template_ptrs[i] = off;
            if (off != 0 and off < buf.len) ch.template_ptrs_count += 1;
        }
        return ch;
    }
};

const RecordIterator = struct {
    chunk: *const Chunk,
    offset: u32,

    fn next(self: *RecordIterator) !?EventRecordRaw {
        if (self.offset == 0 or self.offset + 8 > self.chunk.buf.len) return null;
        // Stop when we reach or pass the free-space region
        if (self.offset >= self.chunk.header.free_space_offset) return null;
        const slice = self.chunk.buf[self.offset..];
        if (!std.mem.eql(u8, slice[0..4], &[_]u8{ 0x2a, 0x2a, 0x00, 0x00 })) return null;
        const size = std.mem.readInt(u32, slice[4..8], .little);
        // Treat structurally bad tail as end-of-records rather than hard error
        if (size < 32) return null;
        // If the record claims to run past the free-space boundary or chunk buffer, stop
        if (self.offset + size > self.chunk.buf.len or (self.offset + size) > self.chunk.header.free_space_offset) return null;
        const identifier = std.mem.readInt(u64, slice[8..16], .little);
        const written = std.mem.readInt(u64, slice[16..24], .little);
        const end_slice = slice[size - 4 .. size][0..4];
        const end_copy = std.mem.readInt(u32, end_slice, .little);
        // Mismatched end size indicates a truncated tail; stop record iteration
        if (end_copy != size) return null;
        const event_data = slice[24 .. size - 4];
        const rec = EventRecordRaw{ .identifier = identifier, .written_time = written, .binxml = event_data, .chunk_buf = &self.chunk.buf };
        self.offset += size;
        return rec;
    }
};

const EventRecordRaw = struct {
    identifier: u64,
    written_time: u64,
    binxml: []const u8,
    chunk_buf: *const [65536]u8,
};

pub const EventRecordView = struct {
    id: u64,
    timestamp_filetime: u64,
    raw_xml: []const u8,
    chunk_buf: *const [65536]u8,

    fn writeXml(self: *const EventRecordView, w: anytype) !void {
        // Buffer per-record output to avoid leaking partial garbage on failures
        var ctx = try binxml.Context.init(std.heap.page_allocator);
        defer ctx.deinit();
        var buf = std.ArrayList(u8).init(std.heap.page_allocator);
        defer buf.deinit();
        var bw = buf.writer();
        try binxml.renderWithContext(&ctx, self.chunk_buf, self.raw_xml, .xml, bw);
        try bw.writeByte('\n');
        try w.writeAll(buf.items);
    }

    const JsonOutMode = enum { single, lines };
    fn writeJson(self: *const EventRecordView, w: anytype, mode: JsonOutMode) !void {
        const body_mode: binxml.RenderMode = switch (mode) {
            .lines => .jsonl,
            .single => .json,
        };
        // Buffer full JSON object per record to avoid corrupting stream on errors
        var buf = std.ArrayList(u8).init(std.heap.page_allocator);
        defer buf.deinit();
        var bw = buf.writer();
        try bw.writeAll("{");
        try bw.print("\"event_record_id\":{d},\"timestamp_filetime\":{d},\"Event\":", .{ self.id, self.timestamp_filetime });
        var ctx = try binxml.Context.init(std.heap.page_allocator);
        defer ctx.deinit();
        try binxml.renderWithContext(&ctx, self.chunk_buf, self.raw_xml, body_mode, bw);
        try bw.writeAll("}\n");
        try w.writeAll(buf.items);
    }
};
