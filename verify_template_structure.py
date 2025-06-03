#!/usr/bin/env python3

import struct

def verify_template_structure():
    """Verify the template structure at offset 550"""
    
    with open('tests/data/security.evtx', 'rb') as f:
        f.seek(0x1000)  # Go to chunk 1
        chunk_data = f.read(0x10000)
        
        # Check template structure at offset 550
        template_offset = 550
        print(f"Template structure at offset {template_offset}:")
        
        # Template structure should be:
        # 0x00: next_offset (4 bytes)
        # 0x04: template_id (4 bytes) 
        # 0x04: guid (16 bytes) - overlaps with template_id
        # 0x14: data_length (4 bytes)
        # 0x18: template_data (variable length)
        
        next_offset = struct.unpack('<L', chunk_data[template_offset:template_offset+4])[0]
        template_id = struct.unpack('<L', chunk_data[template_offset+4:template_offset+8])[0]
        data_length = struct.unpack('<L', chunk_data[template_offset+0x14:template_offset+0x18])[0]
        
        print(f"  next_offset: {next_offset} (0x{next_offset:08x})")
        print(f"  template_id: {template_id}")
        print(f"  data_length: {data_length}")
        
        # Verify this is reasonable
        print(f"\nReasonableness check:")
        print(f"  template_id {template_id} == 3346188909? {template_id == 3346188909}")
        print(f"  data_length {data_length} < 10000? {data_length < 10000}")
        
        if template_id == 3346188909 and data_length < 10000:
            print(f"✅ Template structure looks correct")
            
            # Check the binary XML data starts
            xml_start = template_offset + 0x18
            print(f"\nBinary XML data starts at offset {xml_start}:")
            for i in range(10):
                byte_val = chunk_data[xml_start + i]
                token_name = ""
                if byte_val == 0x0F:
                    token_name = " <- StartOfStream"
                elif byte_val == 0x01:
                    token_name = " <- OpenStartElement"
                elif byte_val == 0x02:
                    token_name = " <- CloseStartElement"
                elif byte_val == 0x00:
                    token_name = " <- EndOfStream or data"
                print(f"    [{xml_start + i}]: 0x{byte_val:02x}{token_name}")
        else:
            print(f"❌ Template structure seems incorrect")
            
            # Maybe the template is at a different offset?
            print(f"\nSearching for template ID {3346188909} in nearby area...")
            target_bytes = struct.pack('<L', 3346188909)
            
            # Search in a range around our current offset
            for search_offset in range(template_offset - 100, template_offset + 100, 4):
                if search_offset >= 0 and search_offset + 4 <= len(chunk_data):
                    if chunk_data[search_offset:search_offset+4] == target_bytes:
                        print(f"  Found template ID at offset {search_offset}")
                        
                        # Check if this looks like a valid template structure
                        potential_length_offset = search_offset + 0x10  # 16 bytes from template_id to data_length
                        if potential_length_offset + 4 <= len(chunk_data):
                            potential_length = struct.unpack('<L', chunk_data[potential_length_offset:potential_length_offset+4])[0]
                            print(f"    Potential data_length: {potential_length}")

if __name__ == "__main__":
    verify_template_structure()