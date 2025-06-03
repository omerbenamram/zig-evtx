# EVTX Template Structure Findings

## Key Discovery: Resident vs Non-Resident Templates

Through analysis of the binary data, we discovered that EVTX records handle templates in two different ways:

### 1. Resident Templates (First Occurrence)

When a template is encountered for the first time in a chunk, the full template binary XML is embedded within the record:

```
Offset  Size   Content
0x00    1      0x0F (StartOfStream token)
0x01    3      StartOfStream data (0x01 0x01 0x00)
0x04    1      0x0C (TemplateInstance token)  
0x05    1      Unknown byte (usually 0x01)
0x06    4      Template ID (e.g., 3346188909)
0x0A    4      Template offset within chunk (e.g., 550)
0x0E    1      0x00 (EndOfStream token)
0x0F    var    [FULL TEMPLATE BINARY XML]
????    var    Substitution Array
```

Example from first record in security.evtx:
- Template Instance ends at offset 14
- Full template binary XML runs from offset 15 to offset 1207
- Substitution array starts at offset 1208 with count = 18

### 2. Non-Resident Templates (Subsequent Uses)

When the same template is used again, the record skips the template content entirely:

```
Offset  Size   Content
0x00    1      0x0F (StartOfStream token)
0x01    3      StartOfStream data (0x01 0x01 0x00)
0x04    1      0x0C (TemplateInstance token)
0x05    1      Unknown byte (usually 0x01)
0x06    4      Template ID (same as before)
0x0A    4      Template offset (same as before)
0x0E    var    Substitution Array (starts immediately!)
```

Example from subsequent records:
- No EndOfStream after TemplateInstance
- Substitution array starts immediately at offset 14

## Substitution Array Structure

The substitution array has a precise format:

```
Offset  Size   Content
0x00    4      Count (DWORD) - number of substitutions
0x04    4*n    Declaration array - one entry per substitution:
               - WORD: size of value in bytes
               - BYTE: variant type
               - BYTE: padding (always 0x00)
????    var    Value data - packed according to declarations
```

### Common Variant Types
- 0x00: Null
- 0x04: UnsignedByte
- 0x06: UnsignedWord  
- 0x08: UnsignedDword
- 0x0A: UnsignedQword
- 0x11: Filetime
- 0x15: HexInt64
- 0x21: WString (UTF-16)
- 0x0F: GUID
- 0x21: BinXml

## Parsing Strategy

To correctly parse records:

1. Read StartOfStream (4 bytes)
2. Read TemplateInstance (10 bytes)
3. Check the next byte:
   - If 0x00 (EndOfStream): This is a resident template
     - Skip the EndOfStream byte
     - Scan forward to find substitution array (look for valid count + declarations)
   - If anything else: This is a non-resident template
     - Substitutions start immediately at current position

4. Parse substitution array:
   - Read count
   - Read declarations
   - Read values according to declarations

## Common Pitfalls

1. **Don't assume EndOfStream always follows TemplateInstance** - It only appears for resident templates

2. **Don't try to parse template binary XML byte-by-byte** - The resident template can be very large (1000+ bytes). Instead, scan for the substitution array pattern.

3. **Validate substitution count** - Should typically be < 100 for valid records

4. **Watch for alignment** - Some values may require alignment padding

## Verification

You can verify the structure using the Python parser:
```python
# First record has resident template
record1 = records[0]  
# Substitutions at offset 1208

# Second record uses same template  
record2 = records[1]
# Substitutions at offset 14
```