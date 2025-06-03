#!/usr/bin/env python3
"""
Debug the exact structure of OpenStartElement
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from Evtx import Evtx as evtx
import Evtx.Nodes as e_nodes

def analyze_openstartlement():
    """Analyze OpenStartElement structure in detail"""
    
    with evtx.Evtx("tests/data/security.evtx") as log:
        chunk = next(log.chunks())
        chunk._load_templates()
        chunk._load_strings()
        
        # Get template binary data
        template_offset = 550
        template = chunk._templates[template_offset]
        data_start = template.offset() + 0x18
        
        print("=== ANALYZING OpenStartElement STRUCTURE ===")
        
        # Get the data after StartOfStream
        pos = data_start + 1  # Skip StartOfStream
        data = chunk._buf[pos:pos + 100]
        
        print(f"\nRaw bytes after StartOfStream:")
        for i in range(0, 32, 8):
            hex_str = ' '.join(f'{b:02x}' for b in data[i:i+8])
            print(f"  {i:02x}: {hex_str}")
        
        # Try different interpretations
        print(f"\n=== INTERPRETATION 1: Python's approach ===")
        # Let's see how Python parses it
        ose = e_nodes.OpenStartElementNode(chunk._buf, data_start + 1, chunk, None)
        print(f"Token: 0x{ose.token():02x}")
        print(f"Flags: 0x{ose.flags():02x}")
        print(f"Unknown0: 0x{ose.unknown0():04x}")
        print(f"Size: {ose.size()}")
        print(f"String offset: {ose.string_offset()}")
        print(f"Tag length: {ose.tag_length()}")
        print(f"Tag name: {ose.tag_name()}")
        
        # Check the string table around that offset
        print(f"\n=== STRING TABLE CHECK ===")
        target_offset = 296448
        print(f"Looking for offset {target_offset} (0x{target_offset:x})")
        
        # Show nearby strings
        print("\nStrings in table:")
        count = 0
        for offset, node in sorted(chunk._strings.items()):
            if count < 10 or abs(offset - target_offset) < 1000:
                print(f"  Offset {offset} (0x{offset:x}): '{node.string()}'")
            count += 1
            
        # Now manually parse the template  
        print(f"\n=== MANUAL PARSE WITH CORRECT STRUCTURE ===")
        
        # After looking at Python code, OpenStartElement structure is:
        # - token (1 byte): 0x01 or 0x41
        # - unknown0 (2 bytes): Usually small number
        # - size (4 bytes): Data size
        # - string_offset (4 bytes): Offset to name
        
        pos = 0
        token = data[pos]
        print(f"Token: 0x{token:02x}")
        pos += 1
        
        unknown0 = int.from_bytes(data[pos:pos+2], 'little')
        print(f"Unknown0: {unknown0}")
        pos += 2
        
        size = int.from_bytes(data[pos:pos+4], 'little')
        print(f"Size: {size}")
        pos += 4
        
        string_offset = int.from_bytes(data[pos:pos+4], 'little')
        print(f"String offset: {string_offset} (0x{string_offset:x})")
        pos += 4
        
        print(f"\nTotal OpenStartElement header: {pos} bytes")
        print(f"Next byte after header: 0x{data[pos]:02x}")
        
        # The issue might be with string offset interpretation
        print(f"\n=== TRYING DIFFERENT STRING OFFSET ===")
        # What if we look at different bytes?
        alt_offset1 = int.from_bytes(data[7:11], 'little')
        alt_offset2 = int.from_bytes(data[4:8], 'little')
        alt_offset3 = 589  # "Event" string offset from logs
        
        print(f"Alternative offset 1 (bytes 7-11): {alt_offset1} (0x{alt_offset1:x})")
        print(f"Alternative offset 2 (bytes 4-8): {alt_offset2} (0x{alt_offset2:x})")
        print(f"Known 'Event' offset: {alt_offset3} (0x{alt_offset3:x})")
        
        for test_offset in [589, 760, 794, 890, 1169, 1606, 2028, 2406]:
            if test_offset in chunk._strings:
                print(f"  String at {test_offset}: '{chunk._strings[test_offset].string()}'")

if __name__ == "__main__":
    analyze_openstartlement()