#!/usr/bin/env python3

import struct

def analyze_bytes():
    """Analyze the exact byte sequence"""
    
    with open('tests/data/security.evtx', 'rb') as f:
        f.seek(0x1000)  # Go to chunk 1
        chunk_data = f.read(0x10000)
        
        # Starting at position 574 (StartOfStream)
        print("Raw bytes starting at 574:")
        for i in range(20):
            pos = 574 + i
            byte_val = chunk_data[pos]
            print(f"  [{pos}]: 0x{byte_val:02x} ({byte_val:3d})")
        
        print("\nToken analysis:")
        print(f"  574: 0x{chunk_data[574]:02x} = StartOfStream")
        
        token_byte = chunk_data[575]
        print(f"  575: 0x{token_byte:02x} = OpenStartElement")
        has_more = (token_byte & 0x40) != 0
        print(f"    has_more flag (bit 6): {has_more}")
        print(f"    token value (bits 0-3): {token_byte & 0x0F}")
        
        # Try different interpretations of the structure
        print(f"\nPossible interpretations starting at 576:")
        
        print(f"Interpretation 1: data at 576 is dependency_id (if has_more)")
        if has_more:
            dep_id = struct.unpack('<H', chunk_data[576:578])[0]
            data_size = struct.unpack('<L', chunk_data[578:582])[0]
            print(f"  dependency_id: {dep_id}")
            print(f"  data_size: {data_size}")
            name_start = 582
        else:
            data_size = struct.unpack('<L', chunk_data[576:580])[0]
            print(f"  data_size: {data_size}")
            name_start = 580
            
        print(f"  NameNode would start at: {name_start}")
        
        print(f"\nInterpretation 2: What if the token format is different?")
        # Maybe the 0x01 at 576 is actually part of a different structure?
        print(f"  Maybe 576-579 form a 4-byte value: 0x{struct.unpack('<L', chunk_data[576:580])[0]:08x}")

if __name__ == "__main__":
    analyze_bytes()