// Token constants (subset)
pub const TOK_FRAGMENT_HEADER: u8 = 0x0f;
pub const TOK_OPEN_START: u8 = 0x01; // or 0x41 with has-more flag
pub const TOK_CLOSE_START: u8 = 0x02;
pub const TOK_CLOSE_EMPTY: u8 = 0x03;
pub const TOK_END_ELEMENT: u8 = 0x04;
pub const TOK_VALUE: u8 = 0x05; // or 0x45 with has-more flag
pub const TOK_ATTRIBUTE: u8 = 0x06; // or 0x46 with has-more flag
pub const TOK_TEMPLATE_INSTANCE: u8 = 0x0c;
pub const TOK_NORMAL_SUBST: u8 = 0x0d;
pub const TOK_OPTIONAL_SUBST: u8 = 0x0e;
pub const TOK_CDATA: u8 = 0x07; // or 0x47 with has-more flag
pub const TOK_CHARREF: u8 = 0x08; // or 0x48 with has-more flag
pub const TOK_ENTITYREF: u8 = 0x09; // or 0x49 with has-more flag
pub const TOK_PITARGET: u8 = 0x0a;
pub const TOK_PIDATA: u8 = 0x0b;

pub inline fn hasMore(flagged: u8, base: u8) bool {
    return (flagged & 0x1f) == base and (flagged & 0x40) != 0;
}
pub inline fn isToken(flagged: u8, base: u8) bool {
    return (flagged & 0x1f) == base;
}

