# EVTX XML Structure and Template System Documentation

## Overview

This document provides comprehensive documentation of the EVTX binary XML format, template system, and substitution mechanisms based on in-depth analysis of both Python and Zig implementations.

## EVTX Binary XML Structure

### File Layout

```
EVTX File Structure:
├── File Header (0x0000-0x1000, 4096 bytes)
│   ├── Magic: "ElfFile\x00" (8 bytes)
│   ├── Oldest chunk number (8 bytes)
│   ├── Current chunk number (8 bytes)
│   ├── Next record number (8 bytes)
│   ├── Header size (4 bytes)
│   ├── Version: 3.1 (2+2 bytes)
│   ├── Header chunk size: 0x1000 (2 bytes)
│   ├── Chunk count (2 bytes)
│   ├── Flags (4 bytes @ 0x70)
│   └── Checksum (4 bytes @ 0x74)
│
└── Chunks (0x1000+, each 65536 bytes)
    ├── Chunk Header (0x0000-0x0200, 512 bytes)
    │   ├── Magic: "ElfChnk\x00" (8 bytes @ 0x00)
    │   ├── Record numbers (32 bytes @ 0x08)
    │   ├── Header size (4 bytes @ 0x28)
    │   ├── Offsets (8 bytes @ 0x2C)
    │   ├── Checksums (8 bytes @ 0x34)
    │   ├── String Table (256 bytes @ 0x80-0x180)
    │   │   └── 64 slots × 4 bytes each
    │   └── Template Table (128 bytes @ 0x180-0x200)
    │       └── 32 slots × 4 bytes each
    │
    └── Records (0x0200+)
        ├── Record Header (24 bytes)
        │   ├── Magic: 0x00002A2A (4 bytes)
        │   ├── Size (4 bytes)
        │   ├── Record number (8 bytes)
        │   ├── Timestamp (8 bytes)
        │   └── Size2 verification (4 bytes @ end)
        │
        └── Record Data
            ├── Binary XML Root Node
            │   ├── Optional StartOfStream (0x0F)
            │   ├── TemplateInstance (0x0C)
            │   └── EndOfStream (0x00)
            └── Substitution Array
```

### Binary XML Token System

#### System Tokens (16 types)

| Token | Value | Description | Structure |
|-------|-------|-------------|-----------|
| EndOfStream | 0x00 | Marks end of XML stream | Single byte |
| OpenStartElement | 0x01 | Opens XML element `<tag>` | Complex structure |
| CloseStartElement | 0x02 | Closes opening tag `>` | Single byte |
| CloseEmptyElement | 0x03 | Self-closing tag `/>` | Single byte |
| CloseElement | 0x04 | Closing tag `</tag>` | Single byte |
| Value | 0x05 | Element text content | Type + variant data |
| Attribute | 0x06 | Element attribute | Name + value |
| CDataSection | 0x07 | CDATA content | Length + data |
| EntityReference | 0x08 | XML entity `&entity;` | String reference |
| CharRef | 0x09 | Character reference | Character code |
| ProcessingInstructionTarget | 0x0A | PI target | String reference |
| ProcessingInstructionData | 0x0B | PI data | String data |
| TemplateInstance | 0x0C | Template reference | ID + offset |
| NormalSubstitution | 0x0D | Value placeholder | Index + type |
| ConditionalSubstitution | 0x0E | Optional placeholder | Index + type |
| StartOfStream | 0x0F | Stream start marker | Single byte |

#### Token Format

Each token byte contains:
- Bits 0-3: Token type (0x00-0x0F)
- Bits 4-7: Flags
- Bit 6: Has more data flag (0x40)

### OpenStartElement Structure

The most complex token, representing an XML element opening:

```
OpenStartElement (0x01):
├── Token byte (1 byte): 0x01 or 0x41 (with has_more flag)
├── Unknown/Dependency (2 bytes): Usually 0x0001
├── Data size (2 bytes): Element data size
├── String offset (4 bytes): Offset to element name in string table
└── Optional: Dependency ID (4 bytes) if flags & 0x04
```

**Critical Discovery**: Data size is 2 bytes, not 4 bytes as some docs suggest.

### String Table Structure

Located at chunk offset 0x80-0x180:

```
String Table:
├── Hash Table (256 bytes)
│   └── 64 slots × 4 bytes (offset to first string in chain)
│
└── String Nodes (variable location in chunk)
    ├── Next offset (4 bytes): Next string in hash chain
    ├── Hash (2 bytes): String hash value
    ├── Length (2 bytes): String length in characters
    ├── String data (UTF-16): Length × 2 bytes
    └── Padding (2 bytes): Always present
```

### Template Table Structure  

Located at chunk offset 0x180-0x200:

```
Template Table:
├── Hash Table (128 bytes)
│   └── 32 slots × 4 bytes (offset to first template in chain)
│
└── Template Nodes (variable location in chunk)
    ├── Next offset (4 bytes): Next template in chain
    ├── Template ID (4 bytes): Unique identifier
    ├── GUID (16 bytes): Overlaps with template ID at +4
    ├── Data length (4 bytes): Binary XML length
    └── Binary XML data (variable): Template definition
```

**Template Verification**: Before offset, check for 0x0C token at offset-10.

## Template System

### Template Discovery Process

1. **Load String Table First**: Required for element name resolution
2. **Scan Template Table**: 32 slots starting at offset 0x180
3. **Follow Chains**: Each slot may have linked templates
4. **Verify Templates**: Check 0x0C marker before parsing
5. **Parse Binary XML**: Convert to format string with placeholders

### Template Processing Flow

```python
# Python implementation flow
1. chunk._load_templates()
   → Scans 32 template slots
   → Follows linked chains
   → Verifies 0x0C markers
   
2. template.parse()
   → Reads template structure
   → Extracts binary XML data
   
3. Views.evtx_template_readable_view()
   → Parses binary XML nodes
   → Generates readable format with substitution markers
   → Example: "[Conditional Substitution(index=14, type=1)]"
   
4. Template._load_xml()
   → Converts markers to Python format strings
   → "[Conditional Substitution(index=14, type=1)]" → "{14:}"
   
5. template.make_substitutions()
   → Applies substitution values using format()
   → "{14:}" + ["Microsoft-Windows-Security-Auditing"] → Final XML
```

### Binary XML Parsing Example

Template ID 3346188909 binary data:
```
0x00: 0F       StartOfStream
0x01: 01       OpenStartElement (Event)
0x02: 01 00    Unknown/dependency
0x04: 41 11    Data size (4417 bytes - seems wrong, actually 2-byte: 0x1141)
0x06: 00 86    String offset continued
0x08: 04 00    
0x0A: 00 4D    String offset (0x4D000486 - wrong byte order?)
...
```

**Actual Structure** (corrected):
```
0x00: 0F          StartOfStream
0x01: 01          OpenStartElement
0x02: 01 00       Unknown = 1
0x04: 41 11       Data size = 0x1141 (4417) - This is wrong!
                  Should be read as 2-byte: 0x0001
0x06: 00 86 04 00 String offset = 0x048600 (296448)
0x0A: 00 4D       Start of next structure
```

### Substitution System

#### Substitution Types

Templates contain placeholders that get replaced with actual values:

1. **Normal Substitution**: Always replaced with value
   - Marker: `[Normal Substitution(index=N, type=T)]`
   - Format: `{N:}`

2. **Conditional Substitution**: Can suppress parent element if NULL
   - Marker: `[Conditional Substitution(index=N, type=T)]`
   - Format: `{N:}`
   - Special handling for NULL values

#### Substitution Array Structure

After binary XML in record:
```
Substitution Array:
├── Count (4 bytes): Number of substitutions
├── Declarations (4 bytes each):
│   ├── Size (2 bytes): Value size
│   └── Type (1 byte): Variant type
│   └── Padding (1 byte)
└── Values (variable size each):
    └── Variant data according to type and size
```

#### Common Substitution Types

From first record analysis:
```
Index  Type  Value
0      0x04  UnsignedByte: 0 (Level)
1      0x04  UnsignedByte: 0 (Opcode)  
2      0x06  UnsignedWord: 12288 (Task)
3      0x06  UnsignedWord: 4608 (EventID)
4      0x06  NULL (Qualifiers)
5      0x15  Hex64: 0x8020000000000000 (Keywords)
6      0x11  Filetime: 2016-07-08 18:12:51
7      0x0F  NULL (ActivityID)
8      0x08  UnsignedDword: 456 (ProcessID)
9      0x08  UnsignedDword: 460 (ThreadID)
10     0x0A  UnsignedQword: 1 (EventRecordID)
11     0x04  UnsignedByte: 0 (Version)
12     0x13  NULL (UserID)
13     0x0F  NULL (RelatedActivityID)
14     0x01  WString: "Microsoft-Windows-Security-Auditing"
15     0x0F  GUID: {54849625-5478-4994-a5ba-3e3b0328c30d}
16     0x01  WString: "Security" (Channel)
17     0x21  BinXml: EventData content
```

## Current Implementation Issues

### 1. Binary XML Parser Stops Early

**Problem**: Parser stops at first EndOfStream (0x00) instead of parsing complete template.

**Current Output**: `<EventData` (10 characters)
**Expected Output**: Complete XML structure (700+ characters)

**Root Cause**: The parser encounters 0x00 at position 3 of OpenStartElement data and treats it as EndOfStream.

### 2. String Resolution Failures

**Problem**: String offsets not found in string table.

**Example**: 
- Template wants string at offset 296448 (0x48600)
- String table lookup returns "not found"
- Falls back to hardcoded "EventData"

**Possible Causes**:
- String offsets might be relative to different base
- String table loading might be incomplete
- Offset byte order interpretation issues

### 3. Template Structure Misinterpretation

**Issue**: OpenStartElement data size being read incorrectly.

**Current**: Reading 0x1141 (4417 bytes) which exceeds template size
**Should be**: Much smaller, likely single-digit bytes

## Debugging Insights

### Key Debugging Commands

```bash
# Python analysis
python3 debug_template_processing.py  # Shows full template workflow
python3 debug_template_rendering.py   # Shows format string generation
python3 python_record_xml.py          # Generates complete XML

# Zig testing  
zig run test_template_comparison.zig  # Compares implementations
zig run debug_parseTemplate.zig       # Step-by-step parsing

# Comparison
echo "=== PYTHON ===" && cat python_record.xml && echo -e "\n=== ZIG ===" && cat zig_template.xml
```

### Critical Discoveries

1. **StartOfStream has no data**: Was consuming extra bytes, causing misalignment
2. **Data size is 2 bytes**: Not 4 bytes as initially implemented  
3. **Templates are pre-parsed**: Not generated on-demand
4. **String table uses hash chains**: Not simple array lookup
5. **All substitutions reference single array**: Shared across template

## Next Steps for Implementation

1. **Fix Binary XML Parser**:
   - Continue parsing past first element
   - Handle nested structures properly
   - Parse complete template structure

2. **Fix String Resolution**:
   - Debug why offsets aren't found
   - Verify string table loading
   - Check offset calculations

3. **Implement Full Template Rendering**:
   - Parse all binary XML tokens
   - Build complete XML tree
   - Generate proper format strings

4. **Add Substitution Processing**:
   - Parse substitution array from records
   - Apply values to template placeholders
   - Handle conditional substitutions

## References

- Python implementation: `/Evtx/` directory
- Zig implementation: `/src/` directory  
- Test files: `/tests/data/security.evtx`
- Debug scripts: Various `debug_*.py` and `*.zig` files