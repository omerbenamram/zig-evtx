#!/usr/bin/env python3
"""
Analyze the exact offset where substitutions start
"""

import sys
import os
import struct

sys.path.insert(0, os.path.dirname(__file__))

from Evtx import Evtx as evtx

def analyze_substitution_position():
    """Analyze where substitutions actually start"""
    
    with evtx.Evtx("tests/data/security.evtx") as log:
        # Get first chunk and record
        chunk = next(log.chunks())
        record = chunk.first_record()
        
        # Get record data
        record_offset = record._offset
        record_size = record.size()
        
        print(f"=== RECORD ANALYSIS ===")
        print(f"Record offset: 0x{record_offset:x}")
        print(f"Record size: {record_size}")
        
        # Read the raw record data
        buf = record._buf
        
        # Skip record header (24 bytes)
        bxml_start = record_offset + 24
        
        print(f"\n=== BINARY XML START ===")
        print(f"Binary XML starts at: 0x{bxml_start:x}")
        
        # Show first 64 bytes of binary XML
        print("\nFirst 64 bytes of binary XML:")
        for i in range(0, 64, 16):
            offset = bxml_start + i
            line = buf[offset:offset+16]
            hex_str = ' '.join(f'{b:02x}' for b in line)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in line)
            print(f"  {i:04x}: {hex_str:<48} {ascii_str}")
        
        # Parse binary XML to find where substitutions start
        pos = bxml_start
        
        # StartOfStream (0x0f)
        token1 = buf[pos]
        print(f"\nToken at pos 0: 0x{token1:02x} (StartOfStream)")
        pos += 1
        # Skip 3 bytes of StartOfStream data
        pos += 3
        
        # TemplateInstance (0x0c)
        token2 = buf[pos]
        print(f"Token at pos 4: 0x{token2:02x} (TemplateInstance)")
        pos += 1
        # Skip template instance data (1 + 4 + 4 bytes)
        pos += 9
        
        # EndOfStream (0x00)
        token3 = buf[pos]
        print(f"Token at pos 14: 0x{token3:02x} (EndOfStream)")
        pos += 1
        
        # Now we should be at substitutions
        print(f"\n=== SUBSTITUTION ARRAY ===")
        print(f"Substitution array starts at byte offset: {pos - bxml_start} from binary XML start")
        print(f"Absolute offset: 0x{pos:x}")
        
        # Read substitution count
        sub_count = struct.unpack('<I', buf[pos:pos+4])[0]
        print(f"Substitution count (dword at offset {pos - bxml_start}): {sub_count}")
        pos += 4
        
        # Show declarations
        print(f"\nDeclarations start at byte offset: {pos - bxml_start}")
        print("Declarations (size, type, padding):")
        for i in range(min(sub_count, 20)):  # Show first 20
            decl_offset = pos - bxml_start
            size = struct.unpack('<H', buf[pos:pos+2])[0]
            typ = buf[pos+2]
            pad = buf[pos+3]
            print(f"  [{i}] at offset {decl_offset}: size={size}, type=0x{typ:02x}, padding=0x{pad:02x}")
            pos += 4
            
        # Calculate where values start
        values_start = bxml_start + 19 + (sub_count * 4)  # 15 + 4 + (count * 4)
        print(f"\nValues should start at byte offset: {values_start - bxml_start}")
        
        # Get the substitutions from Python parser
        root = record.root()
        subs = root.substitutions()
        
        print(f"\n=== PYTHON PARSER RESULTS ===")
        print(f"Python found {len(subs)} substitutions")
        
        # Show where Python thinks the data is
        print(f"\nPython root node offset: 0x{root._offset:x}")
        print(f"Difference from our calculation: {root._offset - bxml_start}")

if __name__ == "__main__":
    analyze_substitution_position()