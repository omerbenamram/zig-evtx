#!/usr/bin/env python

import Evtx.Evtx as evtx

def main():
    with evtx.Evtx("tests/data/security.evtx") as log:
        # Get first record
        record = log.get_record(1)
        root = record.root()
        template = root.template()
        
        print(f"=== PYTHON TEMPLATE OFFSET ANALYSIS ===")
        print(f"Template ID: {template.template_id()}")
        print(f"Template absolute offset (start): {hex(template.absolute_offset(0x0))}")
        print(f"Template data offset (+0x18): {hex(template.absolute_offset(0x18))}")
        print(f"Template data length: {template.data_length()}")
        
        # Get chunk info
        chunk = template._chunk
        print(f"Chunk offset: {hex(chunk.offset())}")
        
        # Check template instance
        template_instance = root.template_instance()
        print(f"Template instance ID: {template_instance.template_id()}")
        print(f"Template instance offset: {template_instance.template_offset()}")
        
        # Calculate absolute offset from chunk
        template_abs_from_chunk = chunk.offset() + template_instance.template_offset()
        print(f"Template absolute offset (calculated): {hex(template_abs_from_chunk)}")
        
        # Show the difference
        python_offset = template.absolute_offset(0x18)
        calculated_offset = template_abs_from_chunk + 0x18
        print(f"\nPython template data starts at: {hex(python_offset)} ({python_offset})")
        print(f"Calculated from chunk+offset: {hex(calculated_offset)} ({calculated_offset})")
        print(f"Difference: {python_offset - calculated_offset}")

if __name__ == "__main__":
    main()