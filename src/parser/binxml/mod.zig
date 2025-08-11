// Public facade for the binxml package. Avoid renderer imports to prevent cycles.
pub const types = @import("types.zig");
pub const tokens = @import("tokens.zig");
pub const Context = @import("context.zig").Context;
pub const Parser = @import("parser.zig").Parser;
pub const Expander = @import("expander.zig").Expander;
pub const Builder = @import("builder.zig").Builder;
pub const common = @import("common.zig");
// Note: renderers should import name helpers directly: @import("name.zig")
