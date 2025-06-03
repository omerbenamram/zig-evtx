# Binary XML Parser Position Tracking Bug Report

## Summary
The Zig EVTX binary XML parser has a critical position tracking inconsistency that causes template parsing to fail with corrupted output. The parser mixes absolute and block-relative offsets, leading to reading data from wrong positions.

## Problem Description
When parsing template 3346188909 at chunk offset 550, the Zig parser generates corrupted 154-character XML instead of the expected 705-character XML that Python generates correctly.

### Expected vs Actual Output
- **Python (correct)**: 705-character well-formed XML
- **Zig (broken)**: 154-character corrupted XML: `'<ROOT<Event EventData="" Event""[Conditional Substitution(index=29440, type=0)]5http://schemas.microsoft.com/win/2004/08/events/eventĂ￿ϖ&unknown;/>/>'`

## Root Cause Analysis

### Position Tracking Inconsistency
The binary XML parser suffers from inconsistent offset schemas:

1. **parseTemplateXml** starts with `pos = 574` (intended as block-relative)
2. **Block.unpackByte(pos)** expects `pos` to be block-relative and reads from `buf[block.offset + pos]`
3. **During parsing**, `pos` becomes absolute (e.g., 659) instead of staying block-relative
4. **This causes reading from wrong positions**, hitting UTF-16 string data as tokens

### Evidence of Position Corruption
```
Template data should start at block-relative position 574
Parser hits EndOfStream at position 659 (absolute)
Position 659 contains 0x00 byte from UTF-16 string "hema" (part of "schemas")
This is NOT a valid EndOfStream token - it's data being misinterpreted as a token
```

### Specific Technical Issues

#### 1. Attribute List Size Reading
- **Expected**: Read attribute list size (0) from position 15 (template-relative)
- **Actual**: Reads value 115 from position 60, which contains UTF-16 string data
- **Result**: Parser skips 115 bytes instead of 0, corrupting position tracking

#### 2. Position Schema Mixing
```
Initial: pos = 574 (block-relative) ✓
Later:   pos = 659 (absolute) ❌
```

#### 3. Block Offset Configuration
- `block.offset` is correctly set to chunk start (0x1000)
- Template offsets from template table are correctly chunk-relative (550)
- Issue is in position advancement during parsing

## Affected Components
- `src/bxml_parser.zig`: Main binary XML parsing logic
- `src/evtx.zig`: Template loading and parsing calls
- All binary XML node parsing functions

## Test Case
Template ID 3346188909 at chunk offset 550 in `tests/data/security.evtx`

### Binary Data Analysis
```
Template 550 structure (confirmed correct):
- Dependency ID: 0x0011
- Data size: 1158  
- Name offset: 589
- Attribute list size: 0 (at position 15)

But Zig reads attribute list size as 115 from wrong position.
```

## Impact
- **Template parsing failures**: Corrupted XML output
- **Record processing failures**: Records can't use corrupted templates  
- **Data loss**: Only partial template data is parsed (154/705 characters)
- **System instability**: Parser may crash on invalid token interpretation

## Debugging Evidence
```
debug: Parsing token byte 0x00 at pos 659
debug: Parsed EndOfStream at depth 0
info: Parsed 25 nodes, output length: 154, final depth: 0
```
Position 659 should contain template data, not be treated as EndOfStream.

## Required Fix
Ensure **consistent position tracking** throughout binary XML parsing:

1. **All positions must use the same schema** (block-relative)
2. **Position increments must be relative sizes**, not absolute offsets  
3. **Verify all `pos.* += value` statements** use correct relative values
4. **Block.unpack* methods expect block-relative positions** consistently

## Files to Modify
- `src/bxml_parser.zig`: Fix position tracking in all parsing functions
- Specifically: `OpenStartElementNode.parse()` attribute list handling
- All node parsing functions that modify `pos.*`

## Success Criteria
Template 3346188909 should generate 705-character XML matching Python output, allowing proper record processing and substitution.