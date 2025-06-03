#!/usr/bin/env python3

import struct

def test_alternative_parsing():
    """Test alternative interpretation of OpenStartElement structure"""
    
    with open('tests/data/security.evtx', 'rb') as f:
        f.seek(0x1000)  # Go to chunk 1
        chunk_data = f.read(0x10000)
        
        # Binary XML starts at offset 574
        pos = 574
        print(f"Alternative parsing starting at {pos}:")
        
        # StartOfStream
        start_token = chunk_data[pos]
        print(f"  {pos}: 0x{start_token:02x} = StartOfStream")
        pos += 1
        
        # OpenStartElement  
        open_token = chunk_data[pos]
        print(f"  {pos}: 0x{open_token:02x} = OpenStartElement")
        pos += 1
        
        # Maybe the structure is different than what I assumed
        # Let's try different interpretations
        
        print(f"\nAlternative 1: Simple data size as 2-byte value")
        data_size_alt1 = struct.unpack('<H', chunk_data[pos:pos+2])[0]
        print(f"  data_size (2 bytes): {data_size_alt1}")
        name_start_alt1 = pos + 2
        
        print(f"\nAlternative 2: Flag + 3-byte data size")
        flag = chunk_data[pos]
        data_size_alt2 = struct.unpack('<L', chunk_data[pos+1:pos+5])[0] & 0xFFFFFF  # 3 bytes
        print(f"  flag: 0x{flag:02x}")
        print(f"  data_size (3 bytes): {data_size_alt2}")
        name_start_alt2 = pos + 4
        
        print(f"\nAlternative 3: What if 0x01 0x00 is the data size?")
        data_size_alt3 = struct.unpack('<H', chunk_data[pos:pos+2])[0]
        print(f"  data_size: {data_size_alt3}")
        name_start_alt3 = pos + 2
        
        # Check what would be at the NameNode positions
        for alt_num, name_start in enumerate([name_start_alt1, name_start_alt2, name_start_alt3], 1):
            print(f"\nAlternative {alt_num} NameNode at {name_start}:")
            if name_start + 6 <= len(chunk_data):
                hash_val = struct.unpack('<H', chunk_data[name_start:name_start+2])[0]
                string_offset = struct.unpack('<L', chunk_data[name_start+2:name_start+6])[0]
                print(f"  hash: 0x{hash_val:04x}")
                print(f"  string_offset: {string_offset} ({'reasonable' if string_offset < 50000 else 'too large'})")

if __name__ == "__main__":
    test_alternative_parsing()