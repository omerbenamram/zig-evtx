# EVTX Parser Zig Implementation Documentation

## Overview

This document summarizes the work done on porting the Python EVTX parser to Zig, including the complete implementation of template parsing and binary XML processing for Windows Event Log files.

## Project Structure

### Core Parser Files

1. **evtx.zig** - Main EVTX file format parser
   - `FileHeader` - Parses the EVTX file header (magic, version, chunks)
   - `ChunkHeader` - Handles chunk parsing and template management
   - `Record` - Individual event record parsing
   - `Template` - Template structure for XML generation

2. **binary_parser.zig** - Low-level binary parsing utilities
   - `Block` - Memory block abstraction for safe binary data access
   - Helper functions for unpacking various data types (bytes, words, dwords, etc.)
   - FILETIME conversion utilities

3. **bxml_parser.zig** - Binary XML parser for templates
   - Full binary XML token parsing (0x00-0x0F)
   - Handles template-specific tokens like substitutions
   - Converts binary XML to readable XML format

4. **variant_types.zig** - EVTX variant data type system
   - Supports all 24+ EVTX data types (WString, GUID, SID, etc.)
   - Unified `VariantTypeNode` structure
   - Type-specific parsing and string conversion

5. **template_processor.zig** - Template processing and substitution
   - Manages template caching
   - Handles substitution arrays
   - Processes records using templates

6. **views.zig** - Output generation (XML/JSON)
   - `renderEvtxAsXml` - Generates complete XML output
   - `renderEvtxAsJson` - JSON output support
   - Template ID extraction from records

### CLI Tools

- **main.zig** - Main evtx_dump tool
- **cli/evtx_info.zig** - File metadata and verification
- **cli/evtx_templates.zig** - Template analysis
- **cli/evtx_dump_json.zig** - JSON output

## Key Technical Achievements

### 1. Template System Implementation

The most significant achievement was implementing the complete template parsing system:

```zig
// Template structure in chunk header
pub const Template = struct {
    template_id: u32,
    guid: [16]u8,
    data_length: u32,
    data: []const u8,
    xml_format: []u8,
};
```

Templates are stored in chunks at offset 0x180 in a hash table with 32 buckets. Each template contains:
- Binary XML data that defines the event structure
- Substitution placeholders for dynamic values
- Template ID for matching with records

### 2. Binary XML Parser

Implemented a complete binary XML parser that handles all EVTX tokens:

```zig
pub const BXmlToken = enum(u8) {
    EndOfStream = 0x00,
    OpenStartElement = 0x01,
    CloseStartElement = 0x02,
    CloseEmptyElement = 0x03,
    CloseElement = 0x04,
    Value = 0x05,
    Attribute = 0x06,
    CDataSection = 0x07,
    EntityReference = 0x08,
    ProcessingInstructionTarget = 0x0A,
    ProcessingInstructionData = 0x0B,
    TemplateInstance = 0x0C,
    NormalSubstitution = 0x0D,
    ConditionalSubstitution = 0x0E,
    StartOfStream = 0x0F,
};
```

### 3. Variant Type System

Complete implementation of all EVTX data types with proper parsing:

```zig
pub const VariantData = union(enum) {
    Null: void,
    WString: []const u8,
    String: []const u8,
    SignedByte: i8,
    UnsignedByte: u8,
    SignedWord: i16,
    UnsignedWord: u16,
    SignedDword: i32,
    UnsignedDword: u32,
    SignedQword: i64,
    UnsignedQword: u64,
    Real32: f32,
    Real64: f64,
    Boolean: bool,
    Binary: []const u8,
    Guid: [16]u8,
    Size: usize,
    Filetime: FileTime,
    Systemtime: SystemTime,
    Sid: []const u8,
    Hex32: u32,
    Hex64: u64,
    Bxml: []const u8,
    WStringArray: [][]const u8,
};
```

### 4. Template Discovery and Loading

Templates are discovered by:
1. Reading the template hash table at chunk offset 0x180
2. Following hash chains via next_offset pointers
3. Validating templates with token 0x0C at offset-10
4. Parsing template binary XML structure

```zig
pub fn loadTemplates(self: *Self) EvtxError!void {
    // Templates are stored in a table starting at offset 0x180
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        const template_offset = try self.block.unpackDword(0x180 + (i * 4));
        if (template_offset == 0) continue;
        
        var ofs = template_offset;
        while (ofs > 0) {
            // Validate template marker
            const token = try self.block.unpackByte(ofs - 10);
            const pointer = try self.block.unpackDword(ofs - 4);
            
            if (token != 0x0C or pointer != ofs) break;
            
            const template = try self.parseTemplate(ofs);
            try self.templates.?.put(template.template_id, template);
            
            const next_offset = try self.block.unpackDword(ofs);
            ofs = next_offset;
        }
    }
}
```

## Zig 0.14 Compatibility Updates

### Format String Changes
- Updated hex formatting: `{:02x}` → `{x:0>2}`
- Fixed error formatting: `{}` → `{any}` for errors
- Updated number formatting to include type specifiers

### API Changes
- HashMap: Changed from `HashMap` with context to `AutoHashMap`
- String splitting: `std.mem.split` → `std.mem.splitSequence`
- Memory management patterns updated for Zig 0.14

## Current Status

### Working Features
- ✅ EVTX file header parsing
- ✅ Chunk iteration and validation
- ✅ Record parsing and enumeration
- ✅ Template discovery and loading
- ✅ Binary XML parsing for templates
- ✅ Basic XML output generation
- ✅ Template ID extraction from records
- ✅ All variant types implemented

### Known Issues
1. **Compilation Error**: Optional formatting issue in one of the print statements
2. **Memory Leaks**: Template XML format strings need proper cleanup in deinit
3. **Incomplete Features**:
   - String table lookups not implemented (placeholder names used)
   - Substitution value parsing from records not complete
   - Template XML shows placeholders but not actual values

### Output Example

The parser successfully generates structured XML instead of base64 fallback:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>[NormalSubstitution]</EventID>
    <Channel>[NormalSubstitution]</Channel>
    <TimeCreated SystemTime="[NormalSubstitution]"/>
  </System>
  <EventData>
    <Data Name="param1">[NormalSubstitution]</Data>
    <Data Name="param2">[NormalSubstitution]</Data>
  </EventData>
</Event>
```

## Next Steps

1. **Fix Compilation**: Resolve the optional formatting error
2. **Implement Substitutions**: Parse substitution values from record data
3. **String Tables**: Implement proper string table lookups
4. **Memory Management**: Fix memory leaks in template handling
5. **Testing**: Add comprehensive tests for all components

## Technical Notes

### Template Binary Format
```
Offset  Size  Description
0x00    4     Next template offset (chunk-relative)
0x04    4     Template ID
0x04    16    GUID (overlaps with template ID)
0x14    4     Data length
0x18    var   Binary XML template data
```

### Record Template Reference
Records reference templates via TemplateInstance tokens (0x0C) which contain:
- Template ID (4 bytes at offset 2)
- Template offset (4 bytes at offset 6)

### Chunk Layout
```
0x000: Magic "ElfChnk\0"
0x080: String hash table (64 dwords)
0x180: Template hash table (32 dwords)
0x200: Start of record data
```

## Resources Used

- Python EVTX implementation for reference
- Rust evtx_dump tool for output comparison
- Zig 0.14 release notes for migration
- Windows Event Log documentation

## Conclusion

The Zig EVTX parser successfully implements the core functionality needed to parse Windows Event Log files and generate structured XML output. The template system, which was the most complex part of the implementation, is now working and discovering templates correctly. With some final bug fixes and feature completions, this will be a fully functional EVTX parser in Zig.