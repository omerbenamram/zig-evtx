#!/usr/bin/env python3
"""
Debug template rendering - shows how binary XML becomes formatted template
"""

import sys
import os
import re

sys.path.insert(0, os.path.dirname(__file__))

from Evtx import Evtx as evtx
import Evtx.Views as e_views
import Evtx.Nodes as e_nodes

def analyze_template_rendering():
    """Show how templates are parsed and rendered"""
    
    with evtx.Evtx("tests/data/security.evtx") as log:
        # Get first chunk and record
        chunk = next(log.chunks())
        record = chunk.first_record()
        root = record.root()
        
        # Get template instance
        template_instance = root.template_instance()
        template_offset = template_instance.template_offset()
        
        print(f"=== TEMPLATE RENDERING ANALYSIS ===")
        print(f"Template ID: {template_instance.template_id()}")
        print(f"Template offset in chunk: {template_offset}")
        
        # Get the template node
        template_node = chunk._templates[template_offset]
        print(f"\n=== RAW TEMPLATE NODE ===")
        print(f"Next offset: {template_node.next_offset()}")
        print(f"Data length: {template_node.data_length()}")
        
        # Show binary data
        print(f"\nTemplate binary data (first 64 bytes):")
        template_data_start = template_node.offset() + 0x18  # Data starts after header
        for i in range(0, min(64, template_node.data_length()), 16):
            data = chunk._buf[template_data_start + i:template_data_start + i + 16]
            hex_str = ' '.join(f'{b:02x}' for b in data)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
            print(f"  {i:04x}: {hex_str:<48} {ascii_str}")
        
        # Parse as binary XML and show structure
        print(f"\n=== TEMPLATE BINARY XML STRUCTURE ===")
        try:
            # Get the readable template format
            template_readable = e_views.evtx_template_readable_view(root)
            print("Template with substitution markers:")
            print(template_readable[:1000] + "..." if len(template_readable) > 1000 else template_readable)
            
            # Count substitutions
            normal_subs = re.findall(r'\[Normal Substitution\(index=(\d+), type=(\d+)\)\]', template_readable)
            cond_subs = re.findall(r'\[Conditional Substitution\(index=(\d+), type=(\d+)\)\]', template_readable)
            
            print(f"\nNormal substitutions: {len(normal_subs)}")
            for idx, (index, type_) in enumerate(normal_subs[:5]):  # Show first 5
                print(f"  [{idx}] index={index}, type={type_}")
            if len(normal_subs) > 5:
                print(f"  ... and {len(normal_subs) - 5} more")
                
            print(f"\nConditional substitutions: {len(cond_subs)}")
            for idx, (index, type_) in enumerate(cond_subs):
                print(f"  [{idx}] index={index}, type={type_}")
            
        except Exception as e:
            print(f"Error parsing template: {e}")
            import traceback
            traceback.print_exc()
        
        # Show how substitutions are applied
        print(f"\n=== SUBSTITUTION APPLICATION ===")
        
        # Get the Template wrapper
        template_wrapper = evtx.Template(template_node)
        template_wrapper._load_xml()
        
        print("Format string after conversion:")
        print(template_wrapper._xml[:500] + "..." if len(template_wrapper._xml) > 500 else template_wrapper._xml)
        
        # Show substitution values
        subs = root.substitutions()
        print(f"\nSubstitution values ({len(subs)} total):")
        for i in range(min(10, len(subs))):
            sub = subs[i]
            try:
                if hasattr(sub, 'string'):
                    value = sub.string()
                elif hasattr(sub, 'xml'):
                    value = sub.xml()
                else:
                    value = str(sub)
                print(f"  {{{i}}}: {value[:50]}{'...' if len(value) > 50 else ''}")
            except:
                print(f"  {{{i}}}: <error>")
        
        if len(subs) > 10:
            print(f"  ... and {len(subs) - 10} more")
        
        # Show final result
        print(f"\n=== FINAL RENDERED XML ===")
        xml = template_wrapper.make_substitutions(subs)
        print(f"Length: {len(xml)} characters")
        print("Content:")
        print(xml)

if __name__ == "__main__":
    analyze_template_rendering()