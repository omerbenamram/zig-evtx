Language Changes
Minor changes:

packed union fields are no longer allowed to specify an align attribute, matching the existing behaviour with packed structs. Providing an override for the alignment previously did not affect the alignment of fields, and migration to these new rules takes the form of deleting the specifier. #22997
usingnamespace Removed
This keyword added distance between the "expected" definition of a declaration and its "actual" definition. Without it, discovering a declaration's definition site is incredibly simple: find the definition of the namespace you are looking in, then find the identifier being defined within that type declaration. With usingnamespace, however, the programmer can be led on a wild goose chase through different types and files.

Carmen the Allocgator
Not only does this harm readability for humans, but it is also problematic for tooling; for instance, Autodoc cannot reasonably see through non-trivial uses of usingnamespace (try looking for dl_iterate_phdr under std.c in the 0.14.1 documentation).

By eliminating this feature, all identifiers can be trivially traced back to where they are imported - by humans and machines alike.

Additionally, usingnamespace encourages poor namespacing. When declarations are stored in a separate file, that typically means they share something in common which is not shared with the contents of another file. As such, it is likely a very reasonable choice to actually expose the contents of that file via a separate namespace, rather than including them in a more general parent namespace. To put it shortly: namespacing is good, actually.

Finally, removal of this feature makes Incremental Compilation fundamentally simpler.

Use Case: Conditional Inclusion
usingnamespace can be used to conditionally include a declaration as follows:

pub usingnamespace if (have_foo) struct {
    pub const foo = 123;
} else struct {};
The solution here is pretty simple: usually, you can just include the declaration unconditionally. Zig's lazy compilation means that it will not be analyzed unless referenced, so there are no problems!

pub const foo = 123;
Occasionally, this is not a good solution, as it lacks safety. Perhaps analyzing foo will always work, but will only give a meaningful result if have_foo is true, and it would be a bug to use it in any other case. In such cases, the declaration can be conditionally made a compile error:

pub const foo = if (have_foo)
    123
else
    @compileError("foo not supported on this target");
This does break feature detection with @hasDecl. If feature detection is needed, a better approach—less prone to typos and bitrotting—is to conditionally initialize the declaration to some "sentinel" value which can be detected. A good choice is often the void value {}:

feature-detection.zig
const something = struct {
    // In this example, `foo` is supported but `bar` is not.
    const have_foo = true;
    const have_bar = false;
    pub const foo = if (have_foo) 123 else {};
    pub const bar = if (have_bar) undefined else {};
};

test "use foo if supported" {
    if (@TypeOf(something.foo) == void) return error.SkipZigTest; // unsupported
    try expect(something.foo == 123);
}

test "use bar if supported" {
    if (@TypeOf(something.bar) == void) return error.SkipZigTest; // unsupported
    try expect(something.bar == 456);
}

const expect = @import("std").testing.expect;
Shell
$ zig test feature-detection.zig
1/2 feature-detection.test.use foo if supported...OK
2/2 feature-detection.test.use bar if supported...SKIP
1 passed; 1 skipped; 0 failed.
Use Case: Implementation Switching
A close cousin of conditional inclusion, usingnamespace can also be used to select from multiple implementations of a declaration at comptime:

pub usingnamespace switch (target) {
    .windows => struct {
        pub const target_name = "windows";
        pub fn init() T {
            // ...
        }
    },
    else => struct {
        pub const target_name = "something good";
        pub fn init() T {
            // ...
        }
    },
};
The alternative to this is simpler and results in better code: make the definition itself a conditional.

pub const target_name = switch (target) {
    .windows => "windows",
    else => "something good",
};
pub const init = switch (target) {
    .windows => initWindows,
    else => initOther,
};
fn initWindows() T {
    // ...
}
fn initOther() T {
    // ...
}
Use Case: Mixins
A very common use case for usingnamespace in the wild was to implement mixins:

/// Mixin to provide methods to manipulate the `count` field.
pub fn CounterMixin(comptime T: type) type {
    return struct {
        pub fn incrementCounter(x: *T) void {
            x.count += 1;
        }
        pub fn resetCounter(x: *T) void {
            x.count = 0;
        }
    };
}

pub const Foo = struct {
    count: u32 = 0,
    pub usingnamespace CounterMixin(Foo);
};
The alternative for this is based on the key observation made above: namespacing is good, actually. The same logic can be applied to mixins. The word "counter" in incrementCounter and resetCounter already kind of is a namespace in spirit—it's like how we used to have std.ChildProcess but have since renamed it to std.process.Child. The same idea can be applied here: what if instead of foo.incrementCounter(), you called foo.counter.increment()?

This can be achieved using a zero-bit field and @fieldParentPtr. Here is the above example ported to use this mechanism:

/// Mixin to provide methods to manipulate the `count` field.
pub fn CounterMixin(comptime T: type) type {
    return struct {
        pub fn increment(m: *@This()) void {
            const x: *T = @alignCast(@fieldParentPtr("counter", m));
            x.count += 1;
        }
        pub fn reset(m: *@This()) void {
            const x: *T = @alignCast(@fieldParentPtr("counter", m));
            x.count = 0;
        }
    };
}

pub const Foo = struct {
    count: u32 = 0,
    counter: CounterMixin(Foo) = .{},
};
This code works just like before, except the usage is foo.counter.increment() rather than foo.incrementCounter(). We have applied namespacing to our mixin using zero-bit fields. In fact, this mechanism is more useful, because it allows you to also include fields! For instance, in this case, we could move the count field to CounterMixin. In this case that actually wouldn't be a mixin at all, since that field is the only state CounterMixin uses—in fact, this is a demonstration that the need for mixins is relatively rare. But in cases where a mixin is appropriate, yet requires additional state, this approach allows using the mixin without needing to duplicate fields at each mixin site.

async and await keywords removed
Also removed @frameSize.

While suspend, resume, and other machinery might remain depending on Proposal: stackless coroutines as low-level primitives, it is settled that there will not be async/await keywords in the language. Instead, they will be in the Standard Library as part of the Io Interface.

switch on non-exhaustive enums
Switching on non-exhaustive enums now allows mixing explicit tags with the _ prong (which represents all the unnamed values):

switch (enum_val) {
    .special_case_1 => foo(),
    .special_case_2 => bar(),
    _, .special_case_3 => baz(),
}
Additionally, it is now allowed to have both else and _:

const Enum = enum(u32) {
    A = 1,
    B = 2,
    C = 44,
    _
};

fn someOtherFunction(value: Enum) void {
    // Does not compile giving "error: else and '_' prong in switch expression"
    switch (value) {
        .A   => {},
        .C   => {},
        else => {}, // Named tags go here (so, .B in this case)
        _    => {}, // Unnamed tags go here
    }
}
Allow more operators on bool vectors
Allow binary not, binary and, binary or, binary xor, and boolean not operators on vectors of bool.

Inline Assembly: Typed Clobbers
Until now these were stringly typed. It's kinda obvious when you think about it.

pub fn syscall1(number: usize, arg1: usize) usize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (number),
          [arg1] "{rdi}" (arg1),
        : "rcx", "r11"
    );
}
⬇️

pub fn syscall1(number: usize, arg1: usize) usize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (number),
          [arg1] "{rdi}" (arg1),
        : .{ .rcx = true, .r11 = true });
}
To auto-upgrade, run zig fmt.

Allow @ptrCast Single-Item Pointer to Slice
This is essentially an extension of the 0.14.0 change which allowed @ptrCast to change the length of a slice. It can now also cast from a single-item pointer to any slice, returning a slice which refers to the same number of bytes as the operand.

ptrcast-single.zig
const std = @import("std");

test "value to byte slice with @ptrCast" {
    const val: u32 = 1;
    const bytes: []const u8 = @ptrCast(&val);
    switch (@import("builtin").target.cpu.arch.endian()) {
        .little => try std.testing.expect(std.mem.eql(u8, bytes, "\x01\x00\x00\x00")),
        .big => try std.testing.expect(std.mem.eql(u8, bytes, "\x00\x00\x00\x01")),
    }
}
Shell
$ zig test ptrcast-single.zig
1/1 ptrcast-single.test.value to byte slice with @ptrCast...OK
All 1 tests passed.
Note that in a future release, it is planned to move this functionality from @ptrCast to a new @memCast builtin, with the intention that the latter is a safer builtin which helps avoid unintentional out-of-bounds memory access. For more information, see issue #23935.

New Rules for Arithmetic on undefined
Zig 0.15.x begins to standardise the rules around how undefined behaves in different contexts—in particular, how it behaves as an operand to arithmetic operators. In summary, only operators which can never trigger Illegal Behavior permit undefined as an operand. Any other operator will trigger Illegal Behavior (or a compile error if evaluated at comptime) if any operand is undefined.

Generally, it is always best practice to avoid any operation on undefined. If you do that, this language change, and any that follow, are unlikely to affect you. If you are affected by this language change, you might see a compile error on code which previously worked:

arith-on-undefined.zig
const a: u32 = 0;
const b: u32 = undefined;

test "arithmetic on undefined" {
    // This addition now triggers a compile error
    _ = a + b;
    // The solution is to simply avoid this operation!
}
Shell
$ zig test arith-on-undefined.zig
src/download/0.15.1/release-notes/arith-on-undefined.zig:6:13: error: use of undefined value here causes illegal behavior
    _ = a + b;
            ^

Error on Lossy Coercion from Int to Float
This compile error has always been intended, but has gone unimplemented until now. The compiler will now emit a compile error if an integer value is coerced to a float at comptime but the integer value could not be precisely represented due to floating-point precision limitations. If you encounter this, you will get a compile error like this:

lossy_int_to_float_coercion.zig
test "big float literal" {
    const val: f32 = 123_456_789;
    _ = val;
}
Shell
$ zig test lossy_int_to_float_coercion.zig
src/download/0.15.1/release-notes/lossy_int_to_float_coercion.zig:2:22: error: type 'f32' cannot represent integer value '123456789'
    const val: f32 = 123_456_789;
                     ^~~~~~~~~~~

The solution is typically just to change an integer literal to a floating-point literal, thereby opting in to floating-point rounding behavior:

lossy_int_to_float_coercion_new.zig
test "big float literal" {
    const val: f32 = 123_456_789.0;
    _ = val;
}
Shell
$ zig test lossy_int_to_float_coercion_new.zig
1/1 lossy_int_to_float_coercion_new.test.big float literal...OK
All 1 tests passed.
Standard Library
Uncategorized changes:

fs.Dir.copyFile no longer can fail with error.OutOfMemory
fs.Dir.atomicFile now requires a write_buffer in the options
fs.AtomicFile now has a File.Writer field rather than File field
fs.File: removed WriteFileOptions, writeFileAll, writeFileAllUnseekable in favor of File.Writer
posix.sendfile removed in favor of fs.File.Reader.sendFile
Writergate
Previous Scandal

All existing std.io readers and writers are deprecated in favor of the newly provided std.Io.Reader and std.Io.Writer which are non-generic and have the buffer above the vtable - in other words the buffer is in the interface, not the implementation. This means that although Reader and Writer are no longer generic, they are still transparent to optimization; all of the interface functions have a concrete hot path operating on the buffer, and only make vtable calls when the buffer is full.

These changes are extremely breaking. I am sorry for that, but I have carefully examined the situation and acquired confidence that this is the direction that Zig needs to go. I hope you will strap in your seatbelt and come along for the ride; it will be worth it.

Motivation
Systems Distributed 2025 Talk: Don't Forget To Flush

The old interface was generic, poisoning structs that contain them and forcing all functions to be generic as well with anytype. The new interface is concrete.
Bonus: the concreteness removes temptation to make APIs operate directly on networking streams, file handles, or memory buffers, giving us a more reusable body of code. For example, http.Server after the change no longer depends on std.net - it operates only on streams now.
The old interface passed errors through rather than defining its own set of error codes. This made errors in streams about as useful as anyerror. The new interface carefully defines precise error sets for each function with actionable meaning.
The new interface has the buffer in the interface, rather than as a separate "BufferedReader" / "BufferedWriter" abstraction. This is more optimizer friendly, particularly for debug mode.
The new interface supports high level concepts such as vectors, splatting, and direct file-to-file transfer, which can propagate through an entire graph of readers and writers, reducing syscall overhead, memory bandwidth, and CPU usage.
The new interface has "peek" functionality - a buffer awareness that offers API convenience for the user as well as simplicity for the implementation.
Adapter API
If you have an old stream and you need a new one, you can use adaptToNewApi() like this:

fn foo(old_writer: anytype) !void {
    var adapter = old_writer.adaptToNewApi(&.{});
    const w: *std.Io.Writer = &adapter.new_interface;
    try w.print("{s}", .{"example"});
    // ...
}
New std.Io.Writer and std.Io.Reader API
These ring buffers have a bunch of handy new APIs that are more convenient, perform better, and are not generic. For instance look at how reading until a delimiter works now:

while (reader.takeDelimiterExclusive('\n')) |line| {
    // do something with line...
} else |err| switch (err) {
    error.EndOfStream, // stream ended not on a line break
    error.StreamTooLong, // line could not fit in buffer
    error.ReadFailed, // caller can check reader implementation for diagnostics
    => |e| return e,
}
These streams also feature some unique concepts compared with other languages' stream implementations:

The concept of discarding when reading: allows efficiently ignoring data. For instance a decompression stream, when asked to discard a large amount of data, can skip decompression of entire frames.
The concept of splatting when writing: this allows a logical "memset" operation to pass through I/O pipelines without actually doing any memory copying, turning an O(M*N) operation into O(M) operation, where M is the number of streams in the pipeline and N is the number of repeated bytes. In some cases it can be even more efficient, such as when splatting a zero value that ends up being written to a file; this can be lowered as a seek forward.
Sending a file when writing: this allows an I/O pipeline to do direct fd-to-fd copying when the operating system supports it.
The stream user provides the buffer, but the stream implementation decides the minimum buffer size. This effectively moves state from the stream implementation into the user's buffer
std.fs.File.Reader and std.fs.File.Writer
std.fs.File.Reader memoizes key information about a file handle such as:

The size from calling stat, or the error that occurred therein.
The current seek position.
The error that occurred when trying to seek.
Whether reading should be done positionally or streaming.
Whether reading should be done via fd-to-fd syscalls (e.g. sendfile)
versus plain variants (e.g. read).
Fulfills the std.Io.Reader interface.

This API turned out to be super handy in practice. Having a concrete type to pass around that memoizes file size is really nice. Most code that previously was calling seek functions on a file handle should be updated to operate on this API instead, causing those seeks to become no-ops thanks to positional reads, while still supporting a fallback to streaming reading.

std.fs.File.Writer is the same idea but for writing.

Upgrading std.io.getStdOut().writer().print()
Please use buffering! And don't forget to flush!

var stdout_buffer: [1024]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
const stdout = &stdout_writer.interface;

// ...

try stdout.print("...", .{});

// ...

try stdout.flush();
reworked std.compress.flate
Carmen the Allocgator
std.compress API restructured everything to do with flate, which includes zlib and gzip. std.compress.flate.Decompress is your main API now and it has a container parameter.

New API example:

var decompress_buffer: [std.compress.flate.max_window_len]u8 = undefined;
var decompress: std.compress.flate.Decompress = .init(reader, .zlib, &decompress_buffer);
const decompress_reader: *std.Io.Reader = &decompress.reader;
If decompress_reader will be piped entirely to a particular *Writer, then give it an empty buffer:

var decompress: std.compress.flate.Decompress = .init(reader, .zlib, &.{});
const n = try decompress.streamRemaining(writer);
Compression functionality was removed. Sorry, you will have to copy the old code into your application, or use a third party package.

It will be nice to get deflate back into the Zig standard library, but for now, progressing the language takes priority over progressing the standard library, and this change is on the path towards locking in the final language design with respect to I/O as an Interface.

Some notable factors:

New implementation does not calculate a checksum since it can be done out-of-band.
New implementation has the fancy match logic replaced with a naive for loop. In the future it would be nice to add a memory copying utility for this that zstd would also use. Despite this, the new implementation performs roughly 10% better in an untar implementation, while reducing compiler code size by 2%. #24614
CountingWriter Deleted
If you were discarding the bytes, use std.Io.Writer.Discarding, which has a count.
If you were allocating the bytes, use std.Io.Writer.Allocating, since you can check how much was allocated.
If you were writing to a fixed buffer, use std.Io.Writer.fixed, and then check the end position.
Otherwise, try not to create an entire node in the stream graph solely for counting bytes. It's very disruptive to optimal buffering.
BufferedWriter Deleted
const stdout_file = std.fs.File.stdout().writer();
var bw = std.io.bufferedWriter(stdout_file);
const stdout = bw.writer();

try stdout.print("Run `zig build test` to run the tests.\n", .{});

try bw.flush(); // Don't forget to flush!
⬇️

var stdout_buffer: [4096]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
const stdout = &stdout_writer.interface;

try stdout.print("Run `zig build test` to run the tests.\n", .{});

try stdout.flush(); // Don't forget to flush!
Consider making your stdout buffer global.

"{f}" Required to Call format Methods
Turn on -freference-trace to help you find all the format string breakage.

Example:

std.debug.print("{}", .{std.zig.fmtId("example")});
This will now cause a compile error:

error: ambiguous format string; specify {f} to call format method, or {any} to skip it
Fixed by:

std.debug.print("{f}", .{std.zig.fmtId("example")});
Motivation: eliminate these two footguns:

Introducing a format method to a struct caused a bug if there was formatting code somewhere that prints with {} and then starts rendering differently.

Removing a format method to a struct caused a bug if there was formatting code somewhere that prints with {} and is now changed without notice.

Now, introducing a format method will cause compile errors at all {} sites. In the future, it will have no effect.

Similarly, eliminating a format method will not change any sites that use {}.

Using {f} always tries to call a format method, causing a compile error if none exists.

Format Methods No Longer Have Format Strings or Options
pub fn format(
    this: @This(),
    comptime format_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void { ... }
⬇️

pub fn format(this: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void { ... }
The deleted FormatOptions are now for numbers only.

Any state that you got from the format string, there are three suggested alternatives:

different format methods
pub fn formatB(foo: Foo, writer: *std.Io.Writer) std.Io.Writer.Error!void { ... }
This can be called with "{f}", .{std.fmt.alt(Foo, .formatB)}.

std.fmt.Alt
pub fn bar(foo: Foo, context: i32) std.fmt.Alt(F, F.baz) {
    return .{ .data = .{ .context = context } };
}
const F = struct {
    context: i32,
    pub fn baz(f: F, writer: *std.Io.Writer) std.Io.Writer.Error!void { ... }
};
This can be called with "{f}", .{foo.bar(1234)}.

return a struct instance that has a format method, combined with {f}.
pub fn bar(foo: Foo, context: i32) F {
    return .{ .context = 1234 };
}
const F = struct {
    context: i32,
    pub fn format(f: F, writer: *std.Io.Writer) std.Io.Writer.Error!void { ... }
};
This can be called with "{f}", .{foo.bar(1234)}.

Formatted Printing No Longer Deals with Unicode
If you were relying on alignment combined with Unicode codepoints, it is now ASCII/bytes only. The previous implementation was not fully Unicode-aware. If you want to align Unicode strings you need full Unicode support which the standard library does not provide.

New Formatted Printing Specifiers
{t} is shorthand for @tagName() and @errorName()
{d} and other integer printing can be used with custom types which calls formatNumber method.
{b64}: output string as standard base64
De-Genericify Linked Lists
With these changes, there's no longer any incentive to hand-roll next/prev pointers. A little bit less bloat too.

Migration guide:

std.DoublyLinkedList(T).Node
⬇️

struct {
    node: std.DoublyLinkedList.Node,
    data: T,
}
Then use @fieldParentPtr to get from node to data.

In many cases there's a better pattern instead which is to put the node intrusively into the data structure. If you're not already doing that, there's a good chance linked list is the wrong data structure.

std.Progress supports progress bar escape codes
Turns out there are escape codes for sending progress status to the terminal.

It integrates with --watch in the Build System to set error state when failures occur, and clear it when they are fixed, also to clear progress when waiting for user input.

std.Progress gains a setStatus function and the following enum:

pub const Status = enum {
    /// Indicates the application is progressing towards completion of a task.
    /// Unless the application is interactive, this is the only status the
    /// program will ever have!
    working,
    /// The application has completed an operation, and is now waiting for user
    /// input rather than calling exit(0).
    success,
    /// The application encountered an error, and is now waiting for user input
    /// rather than calling exit(1).
    failure,
    /// The application encountered at least one error, but is still working on
    /// more tasks.
    failure_working,
};
HTTP Client and Server
These APIs and implementations have been completely reworked.

Server API no longer depends on std.net. Instead, it only depends on std.Io.Reader and std.Io.Writer. It also has all the arbitrary limitations removed. For instance, there is no longer a limit on how many headers can be sent.

var read_buffer: [8000]u8 = undefined;
var server = std.http.Server.init(connection, &read_buffer);
⬇️

var recv_buffer: [4000]u8 = undefined;
var send_buffer: [4000]u8 = undefined;
var conn_reader = connection.stream.reader(&recv_buffer);
var conn_writer = connection.stream.writer(&send_buffer);
var server = std.http.Server.init(conn_reader.interface(), &conn_writer.interface);
Server and Client both share std.http.Reader and std.http.BodyWriter which again only depends on I/O streams and not networking.

Client upgrade example:

var server_header_buffer: [1024]u8 = undefined;
var req = try client.open(.GET, uri, .{
    .server_header_buffer = &server_header_buffer,
});
defer req.deinit();

try req.send();
try req.wait();

const body_reader = try req.reader();
// read from body_reader...

var it = req.response.iterateHeaders();
while (it.next()) |header| {
    _ = header.name;
    _ = header.value;
}
⬇️

var req = try client.request(.GET, uri, .{});
defer req.deinit();

try req.sendBodiless();
var response = try req.receiveHead(&.{});

// Once we call reader() below, strings inside `response.head` are invalidated.
var it = response.head.iterateHeaders();
while (it.next()) |header| {
    _ = header.name;
    _ = header.value;
}

// Optimal size depends on how you will use the reader.
var reader_buffer: [100]u8 = undefined;
const body_reader = response.reader(&reader_buffer);
TLS Client
std.crypto.tls.Client no longer depends on std.net or std.fs. Instead, it only depends on std.Io.Reader and std.Io.Writer.

ArrayList: make unmanaged the default
std.ArrayList -> std.array_list.Managed
std.ArrayListAligned -> std.array_list.AlignedManaged
Warning: these will both eventually be removed entirely.

Having an extra field is more complicated than not having an extra field, so not having it is the null hypothesis. What pattern does having an allocator field allow that not having one doesn't?

avoiding accidentally using the wrong allocator
convenience when you need to pass an allocator also
But there are downsides:

worse method function signatures in the face of reservations
inability to statically initialize
extra memory storage cost, particularly for nested containers
The reasoning goes like this: the upsides are not worth the downsides. Also, given that the correct allocator is always handy, and incorrect use can be trivially safety-checked, the simplicity of only having one implementation is quite valuable compared to the convenience that is gained by having a second implementation.

In practice, this has not been a controversial change with experienced Zig users.

Ring Buffers
There are too many ring buffer implementations in the standard library!

std.fifo.LinearFifo is removed due to being poorly designed. This data structure was unnecessarily generic due to accepting a comptime enum parameter that determined whether its buffer was heap-allocated with an Allocator parameter, passed in as an externally-owned slice, or stored in the struct itself. Each of these different buffer management strategies describes a fundamentally different data structure.

Furthermore, most of its real-world use cases are subsumed by New std.Io.Writer and std.Io.Reader API which are both ring buffers.

Similarly, std.RingBuffer is removed since it was only used by the zstd implementation which has been upgraded to use New std.Io.Writer and std.Io.Reader API.

There was also std.compress.flate.CircularBuffer which was internal to the flate implementation; now deleted.

There was also one each in HTTP Client and Server - again deleted in favor of New std.Io.Writer and std.Io.Reader API.

Even with all five of these deletions, these things pop up like whack-a-mole. Here are some more ring buffers that have been spotted:

lib/std/compress/lzma/decode/lzbuffer.zig - internal to lzma implementation.
lib/std/crypto/tls.zig - made redundant with std.Io.Reader.
lib/std/debug/FixedBufferReader.zig - made redundant by std.Io.Reader's excellent Debug mode performance.
this random pull request - nice try, you almost got away with it!!
Jokes aside, there will likely be room for a general-purpose, reusable ring buffer implementation in the standard library, however, first ask yourself if what you really need is std.Io.Reader or std.Io.Writer.

Removal of BoundedArray
This data structure was popular due to being trivially copyable. However, such convenience comes at a cost.

To upgrade, categorize code based on where the limit comes from:

Is it an arbitrary limit for which the BoundedArray usage is making a reasonable guess at the upper bound, or deciding resource limits? Don't guess. Don't make that choice for the calling code. Accept a buffer as a slice as an input, or use dynamic allocation. (example: the markdown code in #24699)
Is it type safety around a stack buffer? Just use ArrayListUnmanaged. It's fine. It's actually really convenient that this same data structure works here. (example: test_switch_dispatch_loop.zig in #24699)
std.ArrayList now has "Bounded" variants of all the "AssumeCapacity" methods:

var stack = try std.BoundedArray(i32, 8).fromSlice(initial_stack);
⬇️

var buffer: [8]i32 = undefined;
var stack = std.ArrayListUnmanaged(i32).initBuffer(&buffer);
try stack.appendSliceBounded(initial_stack);
Is it an ordered set with a well-defined maximum capacity? Quite rare. Just free-code it. (example: changes to Zcu.zig in #24699)
Is it being used as a growable array that can be copied? This wastes time copying undefined memory all over the place and causes unnecessary generic code bloat.
Deletions and Deprecations
std.fs.File.reader -> std.fs.File.deprecatedReader
std.fs.File.writer -> std.fs.File.deprecatedWriter
std.fmt.fmtSliceEscapeLower -> std.ascii.hexEscape
std.fmt.fmtSliceEscapeUpper -> std.ascii.hexEscape
std.zig.fmtEscapes -> std.zig.fmtString
std.fmt.fmtSliceHexLower -> {x}
std.fmt.fmtSliceHexUpper -> {X}
std.fmt.fmtIntSizeDec -> {B}
std.fmt.fmtIntSizeBin -> {Bi}
std.fmt.fmtDuration -> {D}
std.fmt.fmtDurationSigned -> {D}
std.fmt.Formatter -> std.fmt.Alt
now takes context type explicitly
no fmt string
std.fmt.format -> std.Io.Writer.print
std.io.GenericReader -> std.Io.Reader
std.io.GenericWriter -> std.Io.Writer
std.io.AnyReader -> std.Io.Reader
std.io.AnyWriter -> std.Io.Writer
deleted std.io.SeekableStream
Instead, use *std.fs.File.Reader, *std.fs.File.Writer, or std.ArrayListUnmanaged concrete types, because the implementations will be fundamentally different based on whether you are operating on files or memory.
deleted std.io.BitReader
Bit reading should not be abstracted at this layer; it just makes your hot loop harder to optimize. Tightly couple this code with your stream implementation.
deleted std.io.BitWriter
ditto
deleted std.Io.LimitedReader
deleted std.Io.BufferedReader
deleted std.fifo
