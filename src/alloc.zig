const std = @import("std");
const builtin = @import("builtin");

pub fn get() std.mem.Allocator {
    if (builtin.link_libc) {
        return std.heap.c_allocator;
    }
    return std.heap.smp_allocator;
}

pub fn deinit() void {
    // std.heap.smp_allocator has process lifetime and requires no teardown.
}
