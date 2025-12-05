const std = @import("std");

pub const BinXmlError = error{
    UnexpectedEof,
    BadToken,
    OutOfBounds,
};

/// Error set for BinXML parsing operations.
/// Combines binary parsing errors with allocation failures.
pub const ParseError = BinXmlError || std.mem.Allocator.Error;

/// Error set for std.Io.Writer operations.
pub const WriterError = std.Io.Writer.Error;

/// Error set for rendering operations that involve both parsing and writing.
pub const RenderError = ParseError || WriterError;
