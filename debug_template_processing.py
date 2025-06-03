#!/usr/bin/env python3
"""
Debug template processing - shows exactly how templates and substitutions work
"""

import sys
import os
import struct

sys.path.insert(0, os.path.dirname(__file__))

from Evtx import Evtx as evtx
import Evtx.Views as e_views
import Evtx.Nodes as e_nodes

def show_template_processing():
    """Show detailed template processing workflow"""
    
    with evtx.Evtx("tests/data/security.evtx") as log:
        # Get first chunk
        chunk = next(log.chunks())
        print(f"=== CHUNK ANALYSIS ===")
        print(f"Chunk offset: 0x{chunk._offset:x}")
        
        # Show template table
        print(f"\n=== TEMPLATE TABLE (at offset 0x180) ===")
        for i in range(32):
            offset = chunk.unpack_dword(0x180 + (i * 4))
            if offset > 0:
                print(f"Slot {i}: offset = {offset} (0x{offset:x})")
        
        # Load and show templates
        chunk._load_templates()
        print(f"\n=== LOADED TEMPLATES ===")
        for tid, template in chunk._templates.items():
            print(f"Template ID {tid}:")
            print(f"  Offset: {template._offset - chunk._offset}")
            print(f"  GUID: {template.guid()}")
            print(f"  Data length: {template.data_length()}")
            
            # Show template format (with substitution markers)
            try:
                template_obj = evtx.Template(template)
                template_obj._load_xml()
                print(f"  Format preview: {template_obj._xml[:200]}...")
                
                # Count substitutions
                import re
                subs = re.findall(r'\{(\d+):\}', template_obj._xml)
                print(f"  Substitution count: {len(subs)}")
                print(f"  Substitution indices: {list(set(subs))}")
            except Exception as e:
                print(f"  Error loading XML: {e}")
        
        # Get first record
        print(f"\n=== FIRST RECORD ANALYSIS ===")
        record = chunk.first_record()
        print(f"Record offset: 0x{record._offset:x}")
        print(f"Record number: {record.record_num()}")
        
        # Get root node
        root = record.root()
        print(f"\nRoot node offset: 0x{root._offset:x}")
        
        # Show binary data at root
        print(f"\nBinary data at root (first 32 bytes):")
        for i in range(0, min(32, len(root._buf) - root._offset), 16):
            data = root._buf[root._offset + i:root._offset + i + 16]
            hex_str = ' '.join(f'{b:02x}' for b in data)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
            print(f"  {i:04x}: {hex_str:<48} {ascii_str}")
        
        # Parse template instance
        print(f"\n=== TEMPLATE INSTANCE ===")
        try:
            template_instance = root.template_instance()
            print(f"Template ID: {template_instance.template_id()}")
            print(f"Template offset: {template_instance.template_offset()}")
            print(f"Is resident: {template_instance.is_resident_template()}")
            
            # Get the actual template
            if template_instance.template_offset() in chunk._templates:
                template = chunk._templates[template_instance.template_offset()]
                print(f"Template found in chunk!")
            else:
                print(f"Template NOT in this chunk's template table")
                print(f"Available template offsets: {list(chunk._templates.keys())}")
        except Exception as e:
            print(f"Error parsing template instance: {e}")
        
        # Parse substitutions
        print(f"\n=== SUBSTITUTIONS ===")
        try:
            subs = root.substitutions()
            print(f"Substitution count: {len(subs)}")
            
            for i, sub in enumerate(subs):
                print(f"\nSubstitution {i}:")
                print(f"  Type: {type(sub).__name__}")
                try:
                    if hasattr(sub, 'string'):
                        value = sub.string()
                    elif hasattr(sub, 'xml'):
                        value = sub.xml()
                    else:
                        value = str(sub)
                    print(f"  Value: {value[:100]}{'...' if len(value) > 100 else ''}")
                except Exception as e:
                    print(f"  Error getting value: {e}")
        except Exception as e:
            print(f"Error parsing substitutions: {e}")
            import traceback
            traceback.print_exc()
        
        # Show final XML generation
        print(f"\n=== XML GENERATION ===")
        try:
            xml = record.xml()
            print(f"Final XML length: {len(xml)}")
            print(f"Final XML preview:")
            print(xml[:500] + "..." if len(xml) > 500 else xml)
        except Exception as e:
            print(f"Error generating XML: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    show_template_processing()