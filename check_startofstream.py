#!/usr/bin/env python3

import sys
import struct

def check_startofstream_structure():
    """Check how StartOfStream should be parsed"""
    
    with open('tests/data/security.evtx', 'rb') as f:
        f.seek(0x1000)  # Go to chunk 1
        chunk_data = f.read(0x10000)
        
        # Template binary XML starts at offset 574
        pos = 574
        
        print(f"Binary XML data starting at position {pos}:")
        for i in range(10):
            byte_val = chunk_data[pos + i]
            print(f"  [{pos + i}]: 0x{byte_val:02x} ({byte_val:3d})")
        
        print(f"\nAnalysis:")
        print(f"  Position {pos}: 0x{chunk_data[pos]:02x} = StartOfStream")
        print(f"  Position {pos + 1}: 0x{chunk_data[pos + 1]:02x} = Should be next token (OpenStartElement)")
        
        # According to EVTX spec, StartOfStream is just a marker, no additional data
        print(f"\nStartOfStream should just be the token byte with no additional data")
        print(f"Next token should be at position {pos + 1}")

if __name__ == "__main__":
    check_startofstream_structure()