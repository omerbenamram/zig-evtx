#!/usr/bin/env python3

import sys
import struct
import mmap

def find_real_template_start():
    """Find where template 3346188909 actually starts in the binary data"""
    
    with open('tests/data/system.evtx', 'rb') as f:
        f.seek(0x1000)  # Go to chunk 1
        chunk_data = f.read(0x10000)
        
        # Look for StartOfStream (0x0F) followed by OpenStartElement (0x01) pattern
        target_template_id = 3346188909
        
        print(f"Looking for template ID {target_template_id} (0x{target_template_id:08x})")
        
        # Template storage starts at offset 0x180 in the chunk
        template_area_offset = 0x180
        print(f"Template area starts at chunk offset {template_area_offset}")
        
        # Search for the template ID in the chunk
        template_id_bytes = struct.pack('<L', target_template_id)
        print(f"Looking for bytes: {template_id_bytes.hex()}")
        
        # Find all occurrences of the template ID
        for i in range(len(chunk_data) - 4):
            if chunk_data[i:i+4] == template_id_bytes:
                print(f"Found template ID at chunk offset {i} (0x{i:x})")
                
                # Look backwards for TemplateInstance token (0x0C)
                for j in range(i-1, max(i-20, 0), -1):
                    if chunk_data[j] == 0x0C:
                        print(f"  Found TemplateInstance token (0x0C) at offset {j}")
                        
                        # Read the template offset that follows
                        if j + 9 < len(chunk_data):
                            template_offset = struct.unpack('<L', chunk_data[j+5:j+9])[0]
                            print(f"  Template offset from TemplateInstance: {template_offset}")
                            
                            # Check if this offset has valid binary XML
                            if template_offset < len(chunk_data):
                                print(f"  Checking binary XML at offset {template_offset}:")
                                for k in range(min(10, len(chunk_data) - template_offset)):
                                    byte_val = chunk_data[template_offset + k]
                                    token_name = ""
                                    if byte_val == 0x0F:
                                        token_name = " <- StartOfStream"
                                    elif byte_val == 0x01:
                                        token_name = " <- OpenStartElement"
                                    elif byte_val == 0x00:
                                        token_name = " <- Data or EndOfStream?"
                                    print(f"    [{k}]: 0x{byte_val:02x}{token_name}")
                        break
                
                print()

if __name__ == "__main__":
    find_real_template_start()