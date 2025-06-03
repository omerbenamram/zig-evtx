#!/usr/bin/env python3
"""
Analyze the exact structure of records with resident templates
"""

import sys
import os
import struct

sys.path.insert(0, os.path.dirname(__file__))

from Evtx import Evtx as evtx

def analyze_record_structure():
    """Analyze exact structure of records"""
    
    with evtx.Evtx("tests/data/security.evtx") as log:
        chunk = next(log.chunks())
        
        # Analyze first few records
        records = list(chunk.records())[:5]
        
        for i, record in enumerate(records):
            print(f"\n=== RECORD {i+1} ===")
            print(f"Record offset: 0x{record._offset:x}")
            print(f"Record size: {record.size()}")
            
            # Get binary XML data
            bxml_start = record._offset + 24
            bxml_data = record._buf[bxml_start:record._offset + record.size()]
            
            print(f"\nBinary XML length: {len(bxml_data)}")
            
            # Parse through the structure manually
            pos = 0
            
            # StartOfStream
            token1 = bxml_data[pos]
            print(f"\nPosition {pos}: 0x{token1:02x} (StartOfStream)")
            pos += 4  # StartOfStream is 4 bytes total
            
            # TemplateInstance
            token2 = bxml_data[pos]
            print(f"Position {pos}: 0x{token2:02x} (TemplateInstance)")
            pos += 1
            unknown = bxml_data[pos]
            pos += 1
            template_id = struct.unpack('<I', bxml_data[pos:pos+4])[0]
            pos += 4
            template_offset = struct.unpack('<I', bxml_data[pos:pos+4])[0]
            pos += 4
            print(f"  Template ID: {template_id}")
            print(f"  Template offset: {template_offset}")
            
            # What comes next?
            next_token = bxml_data[pos]
            print(f"\nPosition {pos}: 0x{next_token:02x}")
            
            # Show next 32 bytes
            print(f"\nNext 32 bytes from position {pos}:")
            for j in range(0, min(32, len(bxml_data) - pos), 16):
                line = bxml_data[pos+j:pos+j+16]
                hex_str = ' '.join(f'{b:02x}' for b in line)
                print(f"  {j:04x}: {hex_str}")
            
            # Try to find where substitutions actually start
            # Look for the substitution count pattern
            print(f"\n=== SEARCHING FOR SUBSTITUTION COUNT ===")
            
            # We know from Python that first record has 18 substitutions
            target = 18 if i == 0 else None
            
            for search_pos in range(pos, min(len(bxml_data) - 4, pos + 2000)):
                count = struct.unpack('<I', bxml_data[search_pos:search_pos+4])[0]
                if count == target or (count > 0 and count < 100):
                    print(f"Possible substitution count {count} at position {search_pos} (offset from BXML start)")
                    
                    # Check if this looks like valid declarations
                    if search_pos + 4 + (count * 4) < len(bxml_data):
                        valid = True
                        for k in range(count):
                            decl_pos = search_pos + 4 + (k * 4)
                            if decl_pos + 4 > len(bxml_data):
                                valid = False
                                break
                            size = struct.unpack('<H', bxml_data[decl_pos:decl_pos+2])[0]
                            typ = bxml_data[decl_pos + 2]
                            # Check if type looks valid (should be < 0x30 typically)
                            if typ > 0x30 or size > 1000:
                                valid = False
                                break
                        
                        if valid:
                            print(f"  *** LIKELY SUBSTITUTION START at position {search_pos} ***")
                            # Show first few declarations
                            for k in range(min(5, count)):
                                decl_pos = search_pos + 4 + (k * 4)
                                size = struct.unpack('<H', bxml_data[decl_pos:decl_pos+2])[0]
                                typ = bxml_data[decl_pos + 2]
                                pad = bxml_data[decl_pos + 3]
                                print(f"    Declaration {k}: size={size}, type=0x{typ:02x}, padding=0x{pad:02x}")
                            break

if __name__ == "__main__":
    analyze_record_structure()