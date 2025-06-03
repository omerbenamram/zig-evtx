#!/usr/bin/env python3
"""
Trace exactly how Python parses the binary XML and finds substitutions
"""

import sys
import os
import struct

sys.path.insert(0, os.path.dirname(__file__))

from Evtx import Evtx as evtx
import Evtx.Nodes as nodes

def trace_parsing():
    """Trace Python's parsing step by step"""
    
    with evtx.Evtx("tests/data/security.evtx") as log:
        chunk = next(log.chunks())
        record = chunk.first_record()
        
        print(f"=== RECORD INFO ===")
        print(f"Record offset: 0x{record._offset:x}")
        print(f"Record size: {record.size()}")
        
        # Get the root node
        root = record.root()
        print(f"\n=== ROOT NODE ===")
        print(f"Root type: {type(root).__name__}")
        print(f"Root offset: 0x{root._offset:x}")
        
        # The root should be a RootNode
        if isinstance(root, nodes.RootNode):
            print("\nRootNode structure:")
            
            # Get the template instance
            template_instance = root.template_instance()
            print(f"\nTemplate Instance:")
            print(f"  Offset: 0x{template_instance._offset:x}")
            print(f"  Template ID: {template_instance.template_id()}")
            print(f"  Template offset: {template_instance.template_offset()}")
            
            # The template instance node has a specific structure
            # After the template instance comes the substitution array
            
            # Calculate where substitutions start
            # TemplateInstanceNode is: token(1) + unknown(1) + template_id(4) + template_offset(4) = 10 bytes
            # Plus we need to account for the EndOfStream token after it
            sub_offset = template_instance._offset + 10
            
            # Check for EndOfStream
            eos_byte = root._buf[sub_offset]
            print(f"\nByte at offset 0x{sub_offset:x}: 0x{eos_byte:02x} (should be 0x00 for EndOfStream)")
            sub_offset += 1
            
            print(f"\n=== SUBSTITUTION PARSING ===")
            print(f"Substitutions should start at: 0x{sub_offset:x}")
            
            # Now let's see what's at this position
            print("\nBytes at substitution position:")
            for i in range(0, 32, 16):
                offset = sub_offset + i
                line = root._buf[offset:offset+16]
                hex_str = ' '.join(f'{b:02x}' for b in line)
                print(f"  {i:04x}: {hex_str}")
            
            # Get substitutions through Python
            subs = root.substitutions()
            print(f"\nPython found {len(subs)} substitutions")
            
            # Let's check the SubstitutionArray implementation
            # The key is in how root.substitutions() works
            print("\n=== PYTHON SUBSTITUTION DETAILS ===")
            
            # RootNode has an additional structure
            print(f"Root._chunk: {root._chunk}")
            print(f"Root has resident flag: {hasattr(root, 'resident') and root.resident()}")
            
            # Let's manually parse like Python does
            # The substitution offset calculation in Python is more complex
            # It accounts for the entire BXmlNode structure
            
            # From Python code analysis:
            # 1. RootNode starts with 0x0f00 token and has 4 bytes total
            # 2. After that comes the actual content
            
            # Let's re-examine the structure
            print("\n=== RE-EXAMINING STRUCTURE ===")
            bxml_start = record._offset + 24  # Skip record header
            
            # Read as BXmlNode
            pos = bxml_start
            
            # First 4 bytes should be 0x0f 01 01 00
            first_bytes = struct.unpack('<I', root._buf[pos:pos+4])[0]
            print(f"First 4 bytes at 0x{pos:x}: 0x{first_bytes:08x}")
            
            # This is a RootNode token structure
            # After this comes the template instance
            pos += 4
            
            # Now should be template instance token
            ti_token = root._buf[pos]
            print(f"Token at 0x{pos:x}: 0x{ti_token:02x}")
            
            # Let's find where Python _really_ gets the substitutions from
            # by checking the source code behavior
            print("\n=== ACTUAL SUBSTITUTION OFFSET ===")
            
            # The key insight: root.substitutions() calculates offset differently
            # It uses root.tag_and_children_length() to find where substitutions start
            tag_length = root.tag_and_children_length()
            print(f"Root tag_and_children_length: {tag_length}")
            
            actual_sub_offset = root._offset + tag_length
            print(f"Actual substitution offset: 0x{actual_sub_offset:x}")
            
            # Show what's there
            print("\nBytes at actual substitution position:")
            for i in range(0, 96, 16):
                offset = actual_sub_offset + i
                if offset + 16 <= len(root._buf):
                    line = root._buf[offset:offset+16]
                    hex_str = ' '.join(f'{b:02x}' for b in line)
                    print(f"  {i:04x}: {hex_str}")
            
            # Read the count
            if actual_sub_offset + 4 <= len(root._buf):
                sub_count = struct.unpack('<I', root._buf[actual_sub_offset:actual_sub_offset+4])[0]
                print(f"\nSubstitution count at correct position: {sub_count}")

if __name__ == "__main__":
    trace_parsing()