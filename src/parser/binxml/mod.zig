//! Public facade for the binxml package.
//!
//! The main entry point is `parseRecord`, which parses BinXML data into a fully
//! resolved ElementTree. Template definitions are cached and instantiated with
//! placeholder resolution.
//!
//! Type-safe wrapper types:
//! - `Template`: Cached template definition (may contain Placeholder nodes)
//! - `ElementTree`: Resolved element tree (guaranteed no Placeholder nodes)

pub const types = @import("types.zig");
pub const tokens = @import("tokens.zig");
const context_mod = @import("context.zig");
pub const Context = context_mod.Context;
pub const Template = context_mod.Template;
pub const ElementTree = context_mod.ElementTree;
pub const parser = @import("parser.zig");
pub const reader = @import("../reader.zig");

/// Main entry point: parses a BinXML record into a fully resolved ElementTree.
pub const parseRecord = parser.parseRecord;
