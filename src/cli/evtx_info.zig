const std = @import("std");
const evtx = @import("../evtx.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        std.debug.print("Usage: {s} <evtx_file>\n", .{args[0]});
        std.debug.print("Shows metadata about the event log and verifies checksums.\n", .{});
        std.process.exit(1);
    }

    const filename = args[1];

    var evtx_parser = evtx.Evtx.init(allocator);
    defer evtx_parser.deinit();

    evtx_parser.open(filename) catch |err| {
        std.debug.print("Error opening file {s}: {}\n", .{ filename, err });
        std.process.exit(1);
    };

    if (evtx_parser.getFileHeader()) |header| {
        std.debug.print("File: {s}\n", .{filename});
        std.debug.print("Magic: {s}\n", .{header.magic()});
        std.debug.print("Version: {d}.{d}\n", .{ header.majorVersion(), header.minorVersion() });
        std.debug.print("Header size: {d}\n", .{header.headerSize()});
        std.debug.print("Chunk size: {d}\n", .{header.headerChunkSize()});
        std.debug.print("Chunk count: {d}\n", .{header.chunkCount()});
        std.debug.print("Oldest chunk: {d}\n", .{header.oldestChunk()});
        std.debug.print("Current chunk: {d}\n", .{header.currentChunkNumber()});
        std.debug.print("Next record number: {d}\n", .{header.nextRecordNumber()});
        std.debug.print("Flags: 0x{X:0>8}\n", .{header.flags()});
        std.debug.print("  Dirty: {}\n", .{header.isDirty()});
        std.debug.print("  Full: {}\n", .{header.isFull()});

        // Verify file header
        const file_verified = header.verify() catch false;
        std.debug.print("File header verified: {}\n", .{file_verified});

        // Verify all chunks
        std.debug.print("\nChunk verification:\n", .{});
        var chunk_iter = evtx_parser.chunks();
        var chunk_index: u32 = 0;
        var verified_chunks: u32 = 0;
        var total_records: u64 = 0;

        while (chunk_iter.next()) |chunk| {
            const chunk_verified = chunk.verify() catch false;
            if (chunk_verified) {
                verified_chunks += 1;
            }

            // Count records in this chunk
            var record_iter = chunk.records();
            var chunk_records: u32 = 0;
            while (record_iter.next()) |record| {
                if (record.verify()) {
                    chunk_records += 1;
                }
            }
            total_records += chunk_records;

            std.debug.print("  Chunk {d}: {} ({d} records)\n", .{ chunk_index, chunk_verified, chunk_records });
            chunk_index += 1;
        }

        std.debug.print("\nSummary:\n", .{});
        std.debug.print("  Total chunks: {d}\n", .{chunk_index});
        std.debug.print("  Verified chunks: {d}\n", .{verified_chunks});
        std.debug.print("  Total records: {d}\n", .{total_records});

        if (chunk_index == verified_chunks and file_verified) {
            std.debug.print("  Status: All checks passed ✓\n", .{});
        } else {
            std.debug.print("  Status: Some checks failed ✗\n", .{});
        }
    } else {
        std.debug.print("Error: Could not read file header\n", .{});
        std.process.exit(1);
    }
}
