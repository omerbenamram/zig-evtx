#!/usr/bin/env python3

import sys
import struct
import os

# Add the python-evtx modules to the path
sys.path.insert(0, os.path.dirname(__file__))

from Evtx import Evtx as evtx
from Evtx import Views as e_views

def debug_python_template():
    """Debug template 3346188909 using the Python parser"""
    
    with evtx.Evtx("tests/data/security.evtx") as log:
        fh = log.get_file_header()
        
        # Get chunks
        chunks = []
        for chunk in fh.chunks():
            chunks.append(chunk)
        
        print(f"Found {len(chunks)} chunks")
        
        # Check chunk 1 (second chunk, at offset 0x1000)
        if len(chunks) > 1:
            chunk = chunks[1]
            print(f"Checking chunk 1")
            
            # Load templates  
            template_dict = chunk.templates()
                
            print(f"Found {len(template_dict)} templates in chunk 1")
            
            # Find template 3346188909
            target_id = 3346188909
            if target_id in template_dict:
                template = template_dict[target_id]
                print(f"Found template {target_id}")
                print(f"Template XML: {template.template_xml()}")
            else:
                print(f"Template {target_id} not found")
                print(f"Available templates: {list(template_dict.keys())}")
        else:
            print("Not enough chunks found")

if __name__ == "__main__":
    debug_python_template()

