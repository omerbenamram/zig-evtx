#!/usr/bin/env python3

import sys
import os

# Add the python-evtx modules to the path
sys.path.insert(0, os.path.dirname(__file__))

from Evtx import Evtx as evtx

def debug_first_record():
    """Debug the first record's template ID"""
    
    with evtx.Evtx("tests/data/security.evtx") as log:
        
        # Get the first record
        records = list(log.records())
        if not records:
            print("No records found")
            return
            
        first_record = records[0]
        
        # Extract info about the first record
        print(f"First record info:")
        
        # Try to get template-related info
        try:
            # This might not work, but let's try different approaches
            record_data = first_record.data()
            print(f"Record data length: {len(record_data)} bytes")
            print(f"First 32 bytes: {' '.join(f'{b:02x}' for b in record_data[:32])}")
            
            # Parse the binary XML structure carefully
            if len(record_data) >= 40:
                import struct
                # Binary XML starts at offset 24
                bxml_start = 24
                print(f"Binary XML analysis starting at offset {bxml_start}:")
                print(f"StartOfStream at {bxml_start}: 0x{record_data[bxml_start]:02x}")
                print(f"ROOT marker at {bxml_start+1}: 0x{record_data[bxml_start+1]:02x} 0x{record_data[bxml_start+2]:02x} 0x{record_data[bxml_start+3]:02x}")
                print(f"TemplateInstance at {bxml_start+4}: 0x{record_data[bxml_start+4]:02x}")
                
                # TemplateInstance structure: token(1) + unknown(1) + template_id(4) + template_offset(4)
                ti_pos = bxml_start + 4
                ti_unknown = record_data[ti_pos + 1]
                template_id = struct.unpack('<L', record_data[ti_pos+2:ti_pos+6])[0]
                template_offset = struct.unpack('<L', record_data[ti_pos+6:ti_pos+10])[0] 
                
                print(f"TemplateInstance unknown: 0x{ti_unknown:02x}")
                print(f"Template ID: {template_id}")
                print(f"Template offset: {template_offset}")
                
                # Check what comes after TemplateInstance (at ti_pos + 10)
                next_pos = ti_pos + 10
                print(f"Next 16 bytes after TemplateInstance: {' '.join(f'{b:02x}' for b in record_data[next_pos:next_pos+16])}")
                
                # Check if there's an EndOfStream (0x00) indicating resident template
                if record_data[next_pos] == 0x00:
                    print("Found EndOfStream after TemplateInstance - this record contains a resident template!")
                else:
                    print(f"Next byte after TemplateInstance: 0x{record_data[next_pos]:02x} (not EndOfStream, probably substitutions)")
                
        except Exception as e:
            print(f"Error getting record data: {e}")
        
        # Also check what templates exist in chunk 0
        fh = log.get_file_header()
        chunks = list(fh.chunks())
        print(f"\nFound {len(chunks)} chunks")
        
        if chunks:
            chunk0 = chunks[0]
            templates = list(chunk0.templates())
            print(f"Chunk 0 has {len(templates)} templates: {templates[:10]}")
            
            if len(chunks) > 1:
                chunk1 = chunks[1]
                templates1 = list(chunk1.templates())
                print(f"Chunk 1 has {len(templates1)} templates: {templates1[:10]}")
                
        # Check if template 65807 exists anywhere
        print(f"\nSearching for template 65807 in all chunks...")
        for i, chunk in enumerate(chunks):
            templates = list(chunk.templates())
            if 65807 in templates:
                print(f"Found template 65807 in chunk {i}!")
            # Check the template offset value
            if 65807 in templates:
                template_offset_index = templates.index(65807)
                print(f"Template 65807 is at index {template_offset_index} in chunk {i} template list")

if __name__ == "__main__":
    debug_first_record()