const std = @import("std");
const builtin = @import("builtin");

var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .{};

pub fn get() std.mem.Allocator {
    if (builtin.link_libc) {
        return std.heap.c_allocator;
    }
    return gpa_state.allocator();
}

pub fn deinit() void {
    _ = gpa_state.deinit();
}
