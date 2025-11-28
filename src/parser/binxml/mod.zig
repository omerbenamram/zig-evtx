//! Public facade for the binxml package.
//!
//! The main entry point is `Builder`, which handles parsing BinXML data into an IR
//! (Intermediate Representation) element tree. See `builder.zig` for architecture details.

pub const types = @import("types.zig");
pub const tokens = @import("tokens.zig");
pub const Context = @import("context.zig").Context;
pub const parser = @import("parser.zig");
pub const Builder = @import("builder.zig").Builder;
pub const common = @import("common.zig");
pub const value_reader = @import("value_reader.zig");

// Note: renderers should import name helpers directly via @import("name.zig")
