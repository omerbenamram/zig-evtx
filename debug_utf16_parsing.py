#!/usr/bin/env python3
"""
Debug script to investigate UTF-16 string data being parsed as binary XML tokens.
Focuses on the suspicious value 29440 (0x7300) which appears to be UTF-16 's' character.
"""

import struct
import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

import Evtx.Evtx as evtx
import Evtx.Views as e_views
from Evtx.Nodes import RootNode, TemplateInstanceNode
from Evtx.BinaryParser import hex_dump

def analyze_template_corruption(evtx_file, target_template_id=3346188909):
    """Analyze where UTF-16 string data is being misinterpreted as tokens."""
    
    print(f"=== Analyzing Template {target_template_id} for UTF-16 Parsing Issues ===\n")
    
    fh = evtx.EvtxFile(evtx_file)
    
    for chunk in fh.chunks():
        # Load string table first
        string_table = {}
        for i in range(64):
            offset = 0x80 + (i * 4)
            string_offset = struct.unpack_from("<I", chunk._buf, chunk._offset + offset)[0]
            if string_offset > 0:
                # Store both the offset and the actual string position
                string_table[string_offset] = chunk._offset + string_offset
        
        # Check template table
        for i in range(32):
            offset = 0x180 + (i * 4)
            template_offset = struct.unpack_from("<I", chunk._buf, chunk._offset + offset)[0]
            
            if template_offset == 0 or template_offset == 0xFFFFFFFF:
                continue
            
            current_offset = template_offset
            while current_offset != 0 and current_offset != 0xFFFFFFFF:
                abs_offset = chunk._offset + current_offset
                
                # Read template header
                next_offset = struct.unpack_from("<I", chunk._buf, abs_offset)[0]
                template_id = struct.unpack_from("<I", chunk._buf, abs_offset + 4)[0]
                
                if template_id == target_template_id:
                    print(f"Found template {template_id} at chunk offset 0x{current_offset:04x}")
                    
                    # Get template data length
                    data_length = struct.unpack_from("<I", chunk._buf, abs_offset + 0x14)[0]
                    template_data_start = abs_offset + 0x18
                    
                    print(f"\nTemplate structure:")
                    print(f"  Next offset: 0x{next_offset:08x}")
                    print(f"  Template ID: {template_id}")
                    print(f"  Data length: {data_length} bytes")
                    print(f"  Data starts at: 0x{template_data_start:08x}")
                    
                    # Show template data hex dump
                    print(f"\nTemplate binary XML data (first 200 bytes):")
                    template_data = chunk._buf[template_data_start:template_data_start + min(200, data_length)]
                    print(hex_dump(template_data))
                    
                    # Analyze the corruption point
                    print("\n=== Analyzing Corruption Point ===")
                    
                    # Parse through the template to find where things go wrong
                    pos = 0
                    print(f"\nParsing template tokens:")
                    
                    while pos < len(template_data) and pos < 100:  # First 100 bytes
                        token = template_data[pos]
                        print(f"\nPosition 0x{pos:04x}: Token 0x{token:02x}", end="")
                        
                        if token == 0x0f:  # StartOfStream
                            print(" - StartOfStream (4 bytes)")
                            if pos + 4 <= len(template_data):
                                data = struct.unpack_from("<I", template_data, pos)
                                print(f"  Data: 0x{data[0]:08x}")
                            pos += 4
                            
                        elif token == 0x01 or token == 0x41:  # OpenStartElement
                            print(f" - OpenStartElement {'(has_more)' if token == 0x41 else ''}")
                            if pos + 11 <= len(template_data):
                                unknown0 = struct.unpack_from("<H", template_data, pos + 1)[0]
                                size = struct.unpack_from("<I", template_data, pos + 3)[0]
                                string_offset = struct.unpack_from("<I", template_data, pos + 7)[0]
                                
                                print(f"  Unknown0: 0x{unknown0:04x}")
                                print(f"  Size: {size} bytes")
                                print(f"  String offset: 0x{string_offset:08x}")
                                
                                # Check if string offset points to string table
                                if string_offset in string_table:
                                    print(f"  String offset found in string table!")
                                    string_pos = string_table[string_offset]
                                    # Read string (UTF-16LE with length prefix)
                                    str_len = struct.unpack_from("<H", chunk._buf, string_pos)[0]
                                    string_data = chunk._buf[string_pos + 2:string_pos + 2 + (str_len * 2)]
                                    try:
                                        string_value = string_data.decode('utf-16-le')
                                        print(f"  String value: '{string_value}'")
                                    except:
                                        print(f"  Failed to decode string")
                                else:
                                    print(f"  String offset NOT in string table!")
                                    # Show what's at that offset
                                    if string_offset < len(chunk._buf):
                                        sample = chunk._buf[chunk._offset + string_offset:chunk._offset + string_offset + 20]
                                        print(f"  Data at offset: {sample.hex()}")
                                
                                # Check if next position would read UTF-16 data
                                next_pos = pos + 11
                                if next_pos < len(template_data) - 2:
                                    next_bytes = struct.unpack_from("<H", template_data, next_pos)[0]
                                    print(f"\n  ALERT: Next 2 bytes at position 0x{next_pos:04x}: 0x{next_bytes:04x}")
                                    if next_bytes == 0x7300:  # UTF-16 's'
                                        print(f"  ^^^ This is UTF-16 's' character! Parser is reading string data!")
                                        
                                        # Show surrounding context
                                        context_start = max(0, next_pos - 10)
                                        context_end = min(len(template_data), next_pos + 20)
                                        context = template_data[context_start:context_end]
                                        print(f"\n  Context around corruption (offset 0x{context_start:04x}):")
                                        print(hex_dump(context))
                                        
                                        # Try to decode as UTF-16
                                        try:
                                            utf16_text = context.decode('utf-16-le', errors='ignore')
                                            print(f"  Decoded as UTF-16: '{utf16_text}'")
                                        except:
                                            pass
                                
                            pos += 11
                            
                        elif token == 0x02:  # CloseStartElement
                            print(" - CloseStartElement")
                            pos += 1
                            
                        elif token == 0x00:  # EndOfStream
                            print(" - EndOfStream")
                            print(f"\n*** Parser would stop here at position 0x{pos:04x} ***")
                            
                            # Show what comes after
                            if pos + 20 < len(template_data):
                                print(f"\nData after EndOfStream:")
                                after_data = template_data[pos:pos + 20]
                                print(hex_dump(after_data))
                            break
                            
                        else:
                            print(f" - Unknown/Data byte")
                            # Could be part of element data, check context
                            if pos > 0:
                                prev_token = template_data[pos-1]
                                print(f"  Previous byte: 0x{prev_token:02x}")
                            pos += 1
                    
                    # Find all string references in the template
                    print("\n=== String References in Template ===")
                    for i in range(0, len(template_data) - 4, 4):
                        dword = struct.unpack_from("<I", template_data, i)[0]
                        if dword in string_table:
                            print(f"  Offset 0x{i:04x}: References string at 0x{dword:08x}")
                    
                    return
                
                current_offset = next_offset

if __name__ == "__main__":
    evtx_file = "tests/data/security.evtx"
    analyze_template_corruption(evtx_file)