#!/usr/bin/env python3

def check_token_flags():
    """Check token byte flags in detail"""
    
    with open('tests/data/security.evtx', 'rb') as f:
        f.seek(0x1000)  # Go to chunk 1
        chunk_data = f.read(0x10000)
        
        # Check the token byte at position 575
        token_byte = chunk_data[575]
        print(f"Token byte at 575: 0x{token_byte:02x} = {token_byte:08b} (binary)")
        
        # Check individual bits
        print(f"Bit analysis:")
        print(f"  Bits 0-3 (token): {token_byte & 0x0F} = {(token_byte & 0x0F):04b}")
        print(f"  Bit 4: {(token_byte & 0x10) >> 4}")
        print(f"  Bit 5: {(token_byte & 0x20) >> 5}")
        print(f"  Bit 6 (has_more): {(token_byte & 0x40) >> 6}")
        print(f"  Bit 7: {(token_byte & 0x80) >> 7}")
        
        # The token should be OpenStartElement (1) with no additional flags
        expected_token = 0x01
        if token_byte == expected_token:
            print(f"✅ Token byte matches expected OpenStartElement (0x01)")
        else:
            print(f"❌ Token byte does not match expected OpenStartElement (0x01)")
            
        # Now check what happens if we assume different flag settings
        print(f"\nWhat if this token byte has different meanings?")
        print(f"  As OpenStartElement with has_more=false: read data_size from 576")
        print(f"  As OpenStartElement with has_more=true: read dependency_id from 576, data_size from 578")
        
        # Check both interpretations
        print(f"\nChecking both interpretations:")
        print(f"  If has_more=false:")
        import struct
        data_size_1 = struct.unpack('<L', chunk_data[576:580])[0]
        print(f"    data_size at 576: {data_size_1}")
        
        print(f"  If has_more=true:")
        dep_id = struct.unpack('<H', chunk_data[576:578])[0]
        data_size_2 = struct.unpack('<L', chunk_data[578:582])[0]
        print(f"    dependency_id at 576: {dep_id}")
        print(f"    data_size at 578: {data_size_2}")
        
        # Which one seems more reasonable?
        print(f"\nReasonableness check:")
        print(f"  data_size={data_size_1} seems {'reasonable' if data_size_1 < 10000 else 'too large'}")
        print(f"  data_size={data_size_2} seems {'reasonable' if data_size_2 < 10000 else 'too large'}")

if __name__ == "__main__":
    check_token_flags()