#!/usr/bin/env python3
"""
Debug template corruption issue - trace parsing byte-by-byte
Focus on template ID 3346188909 which shows garbled output
"""

import struct
import Evtx.Evtx as evtx
import Evtx.Views as e_views

def hex_dump(data, base=0):
    """Simple hex dump implementation"""
    lines = []
    for i in range(0, len(data), 16):
        hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[i:i+16])
        lines.append(f"{base+i:08X}  {hex_part:<48}  {ascii_part}")
    return '\n'.join(lines)

def analyze_template_corruption():
    """Analyze the corrupted template parsing"""
    
    # Open the EVTX file
    with evtx.Evtx("tests/data/security.evtx") as log:
        # Get first chunk
        chunk = next(log.chunks())
        
        # Analyze template 3346188909 from the chunk template table (offset 550)
        target_template_id = 3346188909
        print(f"Analyzing template ID: {target_template_id} (0x{target_template_id:08X})")
        print("Getting template from chunk template table at offset 550")
        print("=" * 80)
        
        # Get template from chunk
        template = chunk.get_template(target_template_id)
        if not template:
            print("Template not found in chunk!")
            return
            
        template_data = template.template_data()
        record_with_template = None  # We'll analyze template directly
            
        # If we didn't find resident template in record, load from chunk
        if not template_data:
            print("Loading template from chunk template table...")
            template = chunk.get_template(target_template_id)
            if template:
                template_data = template.template_data()
            else:
                print("Template not found in chunk!")
                return
        
        print(f"\nTemplate data length: {len(template_data)} bytes")
        print("\nFirst 512 bytes of template data:")
        print(hex_dump(template_data[:512]))
        
        # Parse template tokens byte by byte
        print("\n" + "=" * 80)
        print("PARSING TEMPLATE TOKENS:")
        print("=" * 80)
        
        pos = 0
        token_count = 0
        
        while pos < len(template_data):
            if pos >= len(template_data):
                break
                
            token = template_data[pos]
            token_count += 1
            
            print(f"\nToken #{token_count} at offset {pos} (0x{pos:04X}):")
            print(f"  Token: 0x{token:02X}", end="")
            
            # Decode token type
            if token == 0x00:
                print(" - EndOfStream")
                pos += 1
                print(f"  Total parsed: {pos} bytes")
                break
            elif token == 0x01:
                print(" - OpenStartElement")
                if pos + 6 < len(template_data):
                    # Should be 2 bytes for size, not 4!
                    data_size = struct.unpack("<H", template_data[pos+1:pos+3])[0]
                    print(f"  Data size: {data_size} bytes (at offset {pos+1})")
                    
                    # Show the actual data bytes
                    if pos + 3 + data_size <= len(template_data):
                        data_bytes = template_data[pos+3:pos+3+data_size]
                        print(f"  Data bytes: {' '.join(f'{b:02X}' for b in data_bytes[:20])}")
                        if data_size > 20:
                            print(f"  ... ({data_size - 20} more bytes)")
                    
                    pos += 3 + data_size  # 1 (token) + 2 (size) + data
                else:
                    print("  ERROR: Not enough bytes for size")
                    break
            elif token == 0x41:
                print(" - OpenStartElement (has attributes)")
                if pos + 6 < len(template_data):
                    # Should be 2 bytes for size, not 4!
                    data_size = struct.unpack("<H", template_data[pos+1:pos+3])[0]
                    print(f"  Data size: {data_size} bytes")
                    pos += 3 + data_size
                else:
                    print("  ERROR: Not enough bytes")
                    break
            elif token == 0x02:
                print(" - CloseStartElement")
                pos += 1
            elif token == 0x03:
                print(" - CloseEmptyElement")
                pos += 1
            elif token == 0x04:
                print(" - EndElement")
                pos += 1
            elif token == 0x05:
                print(" - Value")
                if pos + 3 < len(template_data):
                    value_type = template_data[pos+1]
                    value_data = struct.unpack("<H", template_data[pos+2:pos+4])[0]
                    print(f"  Type: 0x{value_type:02X}, Data: {value_data}")
                    pos += 4
                else:
                    print("  ERROR: Not enough bytes")
                    break
            elif token == 0x06:
                print(" - Attribute")
                if pos + 3 < len(template_data):
                    data_size = struct.unpack("<H", template_data[pos+1:pos+3])[0]
                    print(f"  Data size: {data_size} bytes")
                    pos += 3 + data_size
                else:
                    print("  ERROR: Not enough bytes")
                    break
            elif token == 0x07:
                print(" - CDATASection")
                if pos + 3 < len(template_data):
                    data_size = struct.unpack("<H", template_data[pos+1:pos+3])[0]
                    print(f"  Data size: {data_size} bytes")
                    pos += 3 + data_size
                else:
                    print("  ERROR: Not enough bytes")
                    break
            elif token == 0x0B:
                print(" - FragmentHeader")
                if pos + 4 < len(template_data):
                    major = template_data[pos+1]
                    minor = template_data[pos+2]
                    flags = template_data[pos+3]
                    print(f"  Version: {major}.{minor}, Flags: 0x{flags:02X}")
                    pos += 4
                else:
                    print("  ERROR: Not enough bytes")
                    break
            elif token == 0x0C:
                print(" - TemplateInstance")
                if pos + 10 < len(template_data):
                    template_id = struct.unpack("<I", template_data[pos+2:pos+6])[0]
                    print(f"  Template ID: {template_id}")
                    pos += 10
                else:
                    print("  ERROR: Not enough bytes")
                    break
            elif token == 0x0D:
                print(" - NormalSubstitution")
                if pos + 4 < len(template_data):
                    subst_index = struct.unpack("<H", template_data[pos+1:pos+3])[0]
                    value_type = template_data[pos+3]
                    print(f"  Index: {subst_index}, Type: 0x{value_type:02X}")
                    pos += 4
                else:
                    print("  ERROR: Not enough bytes")
                    break
            elif token == 0x0E:
                print(" - ConditionalSubstitution")
                if pos + 4 < len(template_data):
                    subst_index = struct.unpack("<H", template_data[pos+1:pos+3])[0]
                    value_type = template_data[pos+3]
                    print(f"  Index: {subst_index}, Type: 0x{value_type:02X}")
                    pos += 4
                else:
                    print("  ERROR: Not enough bytes")
                    break
            elif token == 0x0F:
                print(" - StartOfStream")
                pos += 4  # 1 byte token + 3 reserved bytes
            else:
                print(f" - UNKNOWN TOKEN!")
                # Show next few bytes for context
                context = template_data[pos:pos+16]
                print(f"  Context: {' '.join(f'{b:02X}' for b in context)}")
                
                # Try to guess if this might be data misinterpreted as token
                if token > 0x0F and token < 0x80:
                    print(f"  WARNING: This might be data byte misinterpreted as token!")
                    print(f"  ASCII: '{chr(token) if 32 <= token <= 126 else '?'}'")
                
                # Stop parsing to avoid cascading errors
                break
        
        print(f"\n\nParsing stopped at position {pos} of {len(template_data)} bytes")
        
        if pos < len(template_data):
            print(f"Remaining {len(template_data) - pos} bytes unparsed")
            print("Next 32 bytes:")
            remaining = template_data[pos:pos+32]
            print(hex_dump(remaining))
        
        # Now let's see what Python parser produces
        print("\n" + "=" * 80)
        print("PYTHON PARSER OUTPUT:")
        print("=" * 80)
        
        try:
            # Get the XML from Python parser
            xml_output = e_views.evtx_record_xml_view(record_with_template)
            print(xml_output[:1000])  # First 1000 chars
            if len(xml_output) > 1000:
                print(f"... ({len(xml_output) - 1000} more characters)")
        except Exception as e:
            print(f"Error getting XML: {e}")
        
        # Check for high substitution indices in template
        print("\n" + "=" * 80)
        print("CHECKING FOR HIGH SUBSTITUTION INDICES:")
        print("=" * 80)
        
        max_index = 0
        high_indices = []
        
        pos = 0
        while pos < len(template_data):
            token = template_data[pos]
            
            if token == 0x0D or token == 0x0E:  # Substitution tokens
                if pos + 3 < len(template_data):
                    subst_index = struct.unpack("<H", template_data[pos+1:pos+3])[0]
                    if subst_index > max_index:
                        max_index = subst_index
                    if subst_index > 100:  # Suspiciously high
                        high_indices.append((pos, subst_index))
                    pos += 4
                else:
                    break
            elif token == 0x00:  # EndOfStream
                break
            else:
                # Skip other tokens properly
                if token in [0x01, 0x41, 0x06, 0x07]:  # Variable size tokens
                    if pos + 3 < len(template_data):
                        size = struct.unpack("<H", template_data[pos+1:pos+3])[0]
                        pos += 3 + size
                    else:
                        break
                elif token == 0x0F:  # StartOfStream
                    pos += 4
                elif token == 0x0C:  # TemplateInstance
                    pos += 10
                elif token == 0x0B:  # FragmentHeader
                    pos += 4
                elif token == 0x05:  # Value
                    pos += 4
                else:
                    pos += 1
        
        print(f"Maximum substitution index found: {max_index}")
        if high_indices:
            print(f"Found {len(high_indices)} suspiciously high indices:")
            for pos, idx in high_indices[:5]:  # Show first 5
                print(f"  Position {pos}: index {idx}")
                # Show surrounding bytes
                start = max(0, pos - 8)
                end = min(len(template_data), pos + 8)
                context = template_data[start:end]
                print(f"    Context: {' '.join(f'{b:02X}' for b in context)}")

if __name__ == "__main__":
    analyze_template_corruption()