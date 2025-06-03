#!/usr/bin/env python3

import struct

def debug_namenode_parsing():
    """Debug NameNode structure parsing"""
    
    with open('tests/data/security.evtx', 'rb') as f:
        f.seek(0x1000)  # Go to chunk 1
        chunk_data = f.read(0x10000)
        
        # OpenStartElement should start at position 575
        pos = 575
        print(f"OpenStartElement token at position {pos}: 0x{chunk_data[pos]:02x}")
        
        # Skip the token byte
        pos += 1
        
        # OpenStartElement structure: dependency_id (optional), data_size, NameNode
        print(f"OpenStartElement structure starting at position {pos}:")
        for i in range(16):
            byte_val = chunk_data[pos + i]
            print(f"  [{pos + i}]: 0x{byte_val:02x} ({byte_val:3d})")
        
        # Parse OpenStartElement manually
        print(f"\nManual OpenStartElement parsing:")
        
        # First check if has_more flag was set (it should be in the token byte)
        token_byte = chunk_data[575]
        has_more = (token_byte & 0x40) != 0
        print(f"Token byte: 0x{token_byte:02x}, has_more flag: {has_more}")
        
        current_pos = 576
        
        if has_more:
            dependency_id = struct.unpack('<H', chunk_data[current_pos:current_pos+2])[0]
            print(f"Dependency ID: {dependency_id}")
            current_pos += 2
        
        data_size = struct.unpack('<L', chunk_data[current_pos:current_pos+4])[0]
        print(f"Data size: {data_size}")
        current_pos += 4
        
        # Now parse NameNode
        print(f"NameNode starts at position {current_pos}")
        hash_val = struct.unpack('<H', chunk_data[current_pos:current_pos+2])[0]
        string_offset = struct.unpack('<L', chunk_data[current_pos+2:current_pos+6])[0]
        
        print(f"Hash: 0x{hash_val:04x}")
        print(f"String offset: {string_offset} (0x{string_offset:08x})")
        
        # Check if this looks reasonable
        if string_offset > 0x10000:
            print(f"WARNING: String offset seems too large for chunk size")
            print(f"This might indicate a parsing error")

if __name__ == "__main__":
    debug_namenode_parsing()