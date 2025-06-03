#!/usr/bin/env python3

import sys
import struct
import mmap

def debug_template_binary():
    """Debug the binary XML structure of template 3346188909"""
    
    with open('tests/data/system.evtx', 'rb') as f:
        f.seek(0x1000)  # Go to chunk 1
        chunk_data = f.read(0x10000)
        
        # Template 3346188909 is at chunk offset 550 (0x226)
        template_offset = 550
        
        print(f"Template binary data starting at offset {template_offset}:")
        
        # Show first 32 bytes
        for i in range(32):
            if template_offset + i < len(chunk_data):
                byte_val = chunk_data[template_offset + i]
                print(f"  [{i:2d}]: 0x{byte_val:02x} ({byte_val:3d}) ", end="")
                if byte_val == 0x0F:
                    print("← StartOfStream")
                elif byte_val == 0x01:
                    print("← OpenStartElement") 
                elif byte_val == 0x00:
                    print("← This could be data, not EndOfStream!")
                elif byte_val == 0x02:
                    print("← CloseStartElement")
                elif byte_val == 0x41:
                    print("← ASCII 'A'")
                else:
                    print()
        
        # Let's manually parse the OpenStartElement structure
        print(f"\nManual parsing of OpenStartElement:")
        pos = template_offset
        
        # First byte should be StartOfStream (0x0F)
        start_token = chunk_data[pos]
        print(f"Token at {pos}: 0x{start_token:02x} = {start_token}")
        pos += 1
        
        # Second byte should be OpenStartElement (0x01)  
        open_token = chunk_data[pos]
        print(f"Token at {pos}: 0x{open_token:02x} = {open_token}")
        has_more = (open_token & 0x40) != 0
        print(f"Has more flag: {has_more}")
        pos += 1
        
        # Parse OpenStartElement structure
        if has_more:
            dependency_id = struct.unpack('<H', chunk_data[pos:pos+2])[0]
            print(f"Dependency ID: {dependency_id}")
            pos += 2
        
        data_size = struct.unpack('<L', chunk_data[pos:pos+4])[0]
        print(f"Data size: {data_size}")
        pos += 4
        
        # Parse NameNode
        print(f"NameNode starts at offset {pos}")
        hash_val = struct.unpack('<H', chunk_data[pos:pos+2])[0]
        print(f"Hash: 0x{hash_val:04x}")
        pos += 2
        
        string_offset = struct.unpack('<L', chunk_data[pos:pos+4])[0]
        print(f"String offset: {string_offset}")
        pos += 4
        
        print(f"Next position after NameNode: {pos}")
        if pos < len(chunk_data):
            next_byte = chunk_data[pos]
            print(f"Next byte: 0x{next_byte:02x}")

if __name__ == "__main__":
    debug_template_binary()