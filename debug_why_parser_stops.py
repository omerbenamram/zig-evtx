#!/usr/bin/env python3
"""
Debug why the binary XML parser stops at first EndOfStream
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from Evtx import Evtx as evtx
import Evtx.Nodes as e_nodes

def analyze_parser_behavior():
    """Analyze why parser stops early"""
    
    with evtx.Evtx("tests/data/security.evtx") as log:
        # Get first chunk and template
        chunk = next(log.chunks())
        chunk._load_templates()
        chunk._load_strings()  # Load strings too
        
        # Get template 3346188909 (used by first record)
        template_offset = 550
        template = chunk._templates[template_offset]
        
        print(f"=== ANALYZING TEMPLATE {template.template_id()} ===")
        print(f"Template offset: {template_offset}")
        print(f"Data length: {template.data_length()}")
        
        # Get the binary XML data
        data_start = template.offset() + 0x18
        binary_data = chunk._buf[data_start:data_start + template.data_length()]
        
        print(f"\n=== MANUAL TOKEN PARSING ===")
        pos = 0
        token_count = 0
        node_stack = []
        
        while pos < len(binary_data) and token_count < 50:  # Limit for safety
            if pos >= len(binary_data):
                break
                
            token_byte = binary_data[pos]
            token = token_byte & 0x0F
            flags = token_byte >> 4
            
            token_names = {
                0x00: "EndOfStream",
                0x01: "OpenStartElement",
                0x02: "CloseStartElement", 
                0x03: "CloseEmptyElement",
                0x04: "CloseElement",
                0x05: "Value",
                0x06: "Attribute",
                0x0E: "ConditionalSubstitution",
                0x0F: "StartOfStream"
            }
            
            token_name = token_names.get(token, f"Token_0x{token:02x}")
            indent = "  " * len(node_stack)
            
            print(f"\n{indent}Token {token_count} at pos {pos}:")
            print(f"{indent}  Byte: 0x{token_byte:02x} = {token_name}")
            print(f"{indent}  Next 16 bytes: {' '.join(f'{b:02x}' for b in binary_data[pos:pos+16])}")
            
            # Parse based on token type
            if token == 0x0F:  # StartOfStream
                print(f"{indent}  -> StartOfStream (no additional data)")
                pos += 1
                
            elif token == 0x01:  # OpenStartElement
                pos += 1
                # Read the structure
                if pos + 10 <= len(binary_data):
                    unknown = int.from_bytes(binary_data[pos:pos+2], 'little')
                    data_size = int.from_bytes(binary_data[pos+2:pos+4], 'little')
                    string_offset = int.from_bytes(binary_data[pos+4:pos+8], 'little')
                    
                    print(f"{indent}  -> OpenStartElement:")
                    print(f"{indent}     Unknown: 0x{unknown:04x}")
                    print(f"{indent}     Data size: {data_size}")
                    print(f"{indent}     String offset: {string_offset} (0x{string_offset:x})")
                    
                    # Try to get element name
                    if string_offset in chunk._strings:
                        name = chunk._strings[string_offset].string()
                        print(f"{indent}     Element name: '{name}'")
                    else:
                        print(f"{indent}     Element name: <not found in string table>")
                    
                    node_stack.append(token_name)
                    pos += 8  # Skip the structure we just read
                    
                    # Check if has_more flag suggests attributes
                    if flags & 0x04:
                        print(f"{indent}     Has dependency ID (4 more bytes)")
                        pos += 4
                        
            elif token == 0x02:  # CloseStartElement
                print(f"{indent}  -> CloseStartElement (end of attributes)")
                pos += 1
                
            elif token == 0x03:  # CloseEmptyElement
                print(f"{indent}  -> CloseEmptyElement (self-closing tag)")
                if node_stack:
                    node_stack.pop()
                pos += 1
                
            elif token == 0x04:  # CloseElement
                print(f"{indent}  -> CloseElement")
                if node_stack:
                    closed = node_stack.pop()
                    print(f"{indent}     Closing: {closed}")
                pos += 1
                
            elif token == 0x05:  # Value
                pos += 1
                if pos < len(binary_data):
                    value_type = binary_data[pos]
                    print(f"{indent}  -> Value node, type: 0x{value_type:02x}")
                    pos += 1
                    # Skip actual value parsing for now
                    
            elif token == 0x06:  # Attribute
                pos += 1
                if pos + 4 <= len(binary_data):
                    attr_string_offset = int.from_bytes(binary_data[pos:pos+4], 'little')
                    print(f"{indent}  -> Attribute, string offset: {attr_string_offset}")
                    pos += 4
                    
            elif token == 0x0E:  # ConditionalSubstitution
                pos += 1
                if pos + 3 <= len(binary_data):
                    index = int.from_bytes(binary_data[pos:pos+2], 'little')
                    sub_type = binary_data[pos+2]
                    print(f"{indent}  -> ConditionalSubstitution: index={index}, type=0x{sub_type:02x}")
                    pos += 3
                    
            elif token == 0x00:  # EndOfStream
                print(f"{indent}  -> EndOfStream - STOPPING HERE")
                print(f"{indent}     Node stack depth: {len(node_stack)}")
                print(f"{indent}     Remaining bytes: {len(binary_data) - pos - 1}")
                break
                
            else:
                print(f"{indent}  -> Unknown token 0x{token:02x}, skipping")
                pos += 1
                
            token_count += 1
        
        print(f"\n=== PARSING SUMMARY ===")
        print(f"Total tokens parsed: {token_count}")
        print(f"Final position: {pos}/{len(binary_data)}")
        print(f"Bytes remaining: {len(binary_data) - pos}")
        print(f"Node stack remaining: {node_stack}")
        
        # Show what Python parser produces
        print(f"\n=== PYTHON PARSER RESULT ===")
        from Evtx.Views import evtx_template_readable_view
        root = log.get_record(1).root()
        template_view = evtx_template_readable_view(root)
        print(f"Python template length: {len(template_view)}")
        print("First 500 chars:")
        print(template_view[:500])

if __name__ == "__main__":
    analyze_parser_behavior()