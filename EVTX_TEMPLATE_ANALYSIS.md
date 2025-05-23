# EVTX Template System - Comprehensive Analysis

## Overview

The EVTX (Windows Event Log) file format uses a sophisticated template system to efficiently store and render event data. This document provides a comprehensive analysis of how templates work, based on detailed examination of both Python and Zig implementations.

## Core Concepts

### 1. Binary XML Format

EVTX files store event data in a proprietary binary XML format that consists of:
- **System Tokens** (16 types): Control XML structure (StartOfStream, OpenStartElement, CloseElement, etc.)
- **Variant Types** (24+ types): Store actual data values (WString, UnsignedDword, GUID, etc.)
- **Templates**: Pre-parsed XML structures with substitution placeholders
- **Records**: Event instances that reference templates and provide substitution values

### 2. File Structure Hierarchy

```
EVTX File
├── File Header (0x0 - 0x1000)
│   ├── Magic: "ElfFile\x00"
│   ├── Chunk count
│   └── Checksums
└── Chunks (0x1000+ each 65536 bytes)
    ├── Chunk Header (0x0 - 0x200)
    │   ├── Magic: "ElfChnk\x00"
    │   ├── String Table (0x80 - 0x180): 64 hash slots
    │   └── Template Table (0x180 - 0x200): 32 slots
    └── Records (0x200+)
        ├── Record Header
        ├── Binary XML data
        └── Substitution array
```

## Template Storage and Discovery

### Python Implementation (ChunkHeader._load_templates)

```python
def _load_templates(self):
    """Load templates from chunk header"""
    if self._templates is None:
        self._templates = {}
    
    # Templates stored in 32 slots at offset 0x180
    for i in range(32):
        # Each slot is 4 bytes containing offset to first template in chain
        ofs = self.unpack_dword(0x180 + (i * 4))
        
        while ofs > 0:
            # Verify template marker (0x0C token)
            token = self.unpack_byte(ofs - 10)
            pointer = self.unpack_dword(ofs - 4)
            
            if token != 0x0C or pointer != ofs:
                logger.warning("Unexpected token encountered")
                break
            
            # Parse template at this offset
            template = self.add_template(ofs)
            
            # Follow chain to next template
            ofs = template.next_offset()
```

### Key Template Structure (TemplateNode)

```python
class TemplateNode(BXmlNode):
    # Structure at chunk-relative offset:
    # 0x00: next_offset (4 bytes) - Next template in chain
    # 0x04: template_id (4 bytes) - Unique template identifier
    # 0x04: guid (16 bytes) - GUID overlaps with template_id
    # 0x14: data_length (4 bytes) - Length of binary XML data
    # 0x18: binary_xml_data (variable) - Template definition
```

### Template Verification

Templates are verified before parsing:
1. Check for **0x0C** (TemplateInstance) token at offset-10
2. Verify pointer at offset-4 points to current offset
3. This prevents parsing invalid data as templates

## Binary XML Parsing

### System Tokens (16 types)

```python
class SYSTEM_TOKENS:
    EndOfStreamToken = 0x00
    OpenStartElementToken = 0x01       # <element>
    CloseStartElementToken = 0x02      # > (after attributes)
    CloseEmptyElementToken = 0x03      # />
    CloseElementToken = 0x04           # </element>
    ValueToken = 0x05                  # Element value
    AttributeToken = 0x06              # name="value"
    CDataSectionToken = 0x07           # <![CDATA[...]]>
    EntityReferenceToken = 0x08        # &entity;
    ProcessingInstructionTargetToken = 0x0A
    ProcessingInstructionDataToken = 0x0B
    TemplateInstanceToken = 0x0C       # Template reference
    NormalSubstitutionToken = 0x0D     # {index}
    ConditionalSubstitutionToken = 0x0E # {index} or suppress
    StartOfStreamToken = 0x0F          # Stream start marker
```

### Node Parsing Flow

1. **StartOfStream (0x0F)**: Marker token, no additional data
2. **OpenStartElement (0x01)**:
   - Structure: `token(1) | unknown(2) | size(4) | string_offset(4)`
   - May have dependency_id if flags & 0x04
   - References string table for element name
3. **Attributes**: Follow OpenStartElement, before CloseStartElement
4. **CloseStartElement (0x02)**: Marks end of attributes
5. **Child Elements**: Nested structure
6. **CloseElement (0x04)**: Closes current element
7. **EndOfStream (0x00)**: Marks end of template

### Critical Discovery: StartOfStream Parsing

**Bug Found**: StartOfStream was consuming extra bytes, causing misalignment.

```zig
// INCORRECT - causes parser to read wrong data
pub fn parse(...) BinaryXMLError!StreamNode {
    const unknown0 = try block.unpackByte(pos.*);  // ❌ Wrong!
    pos.* += 1;
    // More incorrect parsing...
}

// CORRECT - StartOfStream is just a marker
pub fn parse(...) BinaryXMLError!StreamNode {
    // Token byte already consumed by caller
    return StreamNode{};  // ✅ No additional data
}
```

## String Table System

### Structure (at chunk offset 0x80)

```
String Table (384 bytes total)
├── 64 hash slots (4 bytes each)
│   └── Each slot: offset to first string in chain
└── String nodes (linked list per slot)
    ├── next_offset (4 bytes)
    ├── hash (2 bytes)
    ├── string_length (2 bytes) 
    └── string_data (UTF-16, variable)
```

### Python String Loading

```python
def _load_strings(self):
    if self._strings is None:
        self._strings = {}
    
    for i in range(64):
        # Get first string offset for this hash slot
        ofs = self.unpack_dword(0x80 + (i * 4))
        
        while ofs > 0:
            # Parse string node
            string_node = self.add_string(ofs)
            self._strings[ofs] = string_node
            
            # Follow chain
            ofs = string_node.next_offset()
```

## Template Processing and Substitutions

### Template Format String Generation

Templates contain binary XML that gets converted to format strings with placeholders:

```python
def _load_xml(self):
    """Convert binary XML to format string"""
    # Replace substitution tokens with Python format placeholders
    matcher = r"\[(?:Normal|Conditional) Substitution\(index=(\d+), type=\d+\)\]"
    self._xml = re.sub(
        matcher, 
        "{\\1:}",  # Convert to {0}, {1}, etc.
        self._template_node.template_format()
    )
```

### Substitution Array Structure

Records contain a substitution array after the binary XML:

```python
def substitutions(self):
    """Parse substitution array from record"""
    sub_decl = []  # Size and type declarations
    sub_def = []   # Actual variant values
    
    ofs = self.tag_and_children_length()
    sub_count = self.unpack_dword(ofs)
    ofs += 4
    
    # Read declarations
    for _ in range(sub_count):
        size = self.unpack_word(ofs)
        type_ = self.unpack_byte(ofs + 0x2)
        sub_decl.append((size, type_))
        ofs += 4
    
    # Read actual values
    for size, type_ in sub_decl:
        val = get_variant_value(self._buf, self.offset() + ofs, 
                               self._chunk, self, type_, length=size)
        sub_def.append(val)
        ofs += size
    
    return sub_def
```

### Applying Substitutions

```python
def make_substitutions(self, substitutions):
    """Apply substitutions to template format string"""
    self._load_xml()  # Ensure format string is ready
    # Format string has {0}, {1}, etc. placeholders
    return self._xml.format(*[n.xml() for n in substitutions])
```

## Record Processing Workflow

### 1. Record Structure

```
Record
├── Magic (4 bytes): 0x00002A2A
├── Size (4 bytes)
├── Record Number (8 bytes)
├── Timestamp (8 bytes)
├── Binary XML Root Node
│   ├── Optional StartOfStream (0x0F)
│   ├── TemplateInstance (0x0C)
│   │   ├── Unknown (1 byte)
│   │   ├── Template ID (4 bytes)
│   │   └── Template Offset (4 bytes)
│   └── Substitution Array
└── Size2 (4 bytes) - Must match Size
```

### 2. Template Resolution

```python
def template(self):
    """Get template for this record"""
    # Parse template instance from record
    instance = self.template_instance()
    
    # Get template from chunk
    offset = self._chunk.offset() + instance.template_offset()
    node = TemplateNode(self._buf, offset, self._chunk, instance)
    return node
```

### 3. XML Generation (Views.py)

```python
def evtx_record_xml_view(record):
    """Render record as XML"""
    return render_root_node(record.root())

def render_root_node(root_node):
    """Apply substitutions and generate XML"""
    # Get substitutions from record
    subs = root_node.substitutions()
    
    # Get template and apply substitutions
    return render_root_node_with_subs(root_node, subs)
```

## Cross-Chunk Template References

**Important Discovery**: Records can reference templates from different chunks.

Example from debugging:
- Record in chunk 0 references template ID 65807
- Template 65807 doesn't exist in chunk 0
- Must search other chunks or handle missing templates

This explains why some records fail to render - they reference templates that:
1. Are in different chunks (requires cross-chunk lookup)
2. Were deleted/corrupted
3. Use a different template ID scheme

## Variant Type System (24+ types)

### Common Types in EVTX

```python
NODE_TYPES:
    NULL = 0x00          # Empty value
    WSTRING = 0x01       # UTF-16 string
    STRING = 0x02        # ASCII string
    UNSIGNED_DWORD = 0x08  # 32-bit unsigned
    UNSIGNED_QWORD = 0x0A  # 64-bit unsigned
    GUID = 0x0F          # 128-bit GUID
    FILETIME = 0x11      # Windows FILETIME
    SID = 0x13           # Security Identifier
    BXML = 0x21          # Binary XML
    WSTRINGARRAY = 0x81  # Array of WStrings
```

### Variant Parsing

Each variant type has specific parsing rules:

```python
def get_variant_value(buf, offset, chunk, parent, type_, length=None):
    """Parse variant based on type"""
    types = {
        NODE_TYPES.NULL: NullTypeNode,
        NODE_TYPES.WSTRING: WstringTypeNode,
        NODE_TYPES.UNSIGNED_DWORD: UnsignedDwordTypeNode,
        # ... 20+ more types
    }
    
    TypeClass = types[type_]
    return TypeClass(buf, offset, chunk, parent, length=length)
```

## Key Implementation Challenges

### 1. Template Discovery
- Templates stored in hash table with potential collisions
- Linked list traversal required
- Must verify 0x0C token before parsing

### 2. String Resolution
- Offsets are chunk-relative
- Hash collisions possible
- UTF-16 to UTF-8 conversion needed

### 3. Binary XML Parsing
- Token interpretation depends on context
- Variable-length structures
- Nested element tracking required

### 4. Memory Management
- Templates should be cached
- Strings need proper cleanup
- Substitution arrays are temporary

### 5. Cross-Chunk References
- Global template registry needed
- Fallback mechanisms for missing templates
- Version compatibility issues

## Debugging Methodology

### 1. Byte-by-Byte Comparison
Compare Python and Zig parsing at each step:
```bash
# Python
print(f"Token at {pos}: 0x{token:02x}")

# Zig
std.log.debug("Token at {}: 0x{x:0>2}", .{pos, token});
```

### 2. Structure Verification
Always verify expected markers:
- File magic: "ElfFile\x00"
- Chunk magic: "ElfChnk\x00"
- Record magic: 0x00002A2A
- Template token: 0x0C

### 3. Incremental Testing
1. Parse structure headers
2. Load string tables
3. Discover templates
4. Parse binary XML
5. Apply substitutions

## Conclusion

The EVTX template system is a sophisticated mechanism for efficient event storage and rendering. Key insights:

1. **Templates are pre-parsed**: Binary XML is parsed once and stored with placeholders
2. **String deduplication**: Common strings stored once in hash table
3. **Lazy evaluation**: Templates loaded on-demand
4. **Version flexibility**: Template IDs allow schema evolution
5. **Space efficiency**: Records only store unique data as substitutions

The main challenge in implementing a compatible parser is handling all edge cases and maintaining exact compatibility with the binary format's quirks.