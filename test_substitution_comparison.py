#!/usr/bin/env python3
"""
Compare Python and Zig substitution parsing for the first record
"""

import sys
import os
import subprocess

# Add the python-evtx modules to the path
sys.path.insert(0, os.path.dirname(__file__))

from Evtx import Evtx as evtx


def get_python_substitutions():
    """Get substitutions from Python parser"""
    with evtx.Evtx("tests/data/security.evtx") as log:
        # Get first chunk and record
        chunk = next(log.chunks())
        record = chunk.first_record()
        root = record.root()
        
        print("=== PYTHON SUBSTITUTIONS ===")
        print(f"Record number: {record.record_num()}")
        
        # Get template instance
        template_instance = root.template_instance()
        print(f"Template ID: {template_instance.template_id()}")
        print(f"Template offset: {template_instance.template_offset()}")
        
        # Get substitutions
        subs = root.substitutions()
        print(f"\nSubstitution count: {len(subs)}")
        
        for i, sub in enumerate(subs):
            print(f"\nSubstitution [{i}]:")
            print(f"  Type: {type(sub).__name__}")
            
            # Get the raw value
            if hasattr(sub, 'string'):
                value = sub.string()
            elif hasattr(sub, 'xml'):
                value = sub.xml()
            elif hasattr(sub, '_buf'):
                # For numeric types, show the raw buffer
                buf_hex = ' '.join(f'{b:02x}' for b in sub._buf[sub._offset:sub._offset+16])
                value = f"buffer: {buf_hex}"
            else:
                value = str(sub)
                
            print(f"  Value: {value}")
            
            # Also show variant type info if available
            if hasattr(sub, 'type'):
                print(f"  Variant type: 0x{sub.type():02x}")
        
        # Show the final XML
        print("\n=== FINAL PYTHON XML ===")
        xml = record.xml()
        print(xml)
        
        return subs, xml


def run_zig_test():
    """Run the Zig implementation and capture output"""
    print("\n=== BUILDING ZIG ===")
    result = subprocess.run(['zig', 'build'], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Build failed: {result.stderr}")
        return None
        
    print("\n=== ZIG OUTPUT ===")
    result = subprocess.run(
        ['./zig-out/bin/evtx_dump', 'tests/data/security.evtx'],
        capture_output=True, 
        text=True
    )
    
    # Extract just the first record XML (between first <Event> and </Event>)
    output = result.stdout
    if '<Event>' in output:
        start = output.find('<Event>')
        end = output.find('</Event>', start) + 8
        if end > start:
            zig_xml = output[start:end]
            print(f"Zig XML: {zig_xml}")
            return zig_xml
    
    print(f"Zig stdout: {result.stdout[:500]}")
    print(f"Zig stderr: {result.stderr[:500]}")
    return None


def compare_results():
    """Compare Python and Zig results"""
    python_subs, python_xml = get_python_substitutions()
    zig_xml = run_zig_test()
    
    print("\n=== COMPARISON ===")
    print(f"Python XML length: {len(python_xml)}")
    print(f"Zig XML length: {len(zig_xml) if zig_xml else 0}")
    
    if zig_xml and "Failed to parse substitutions" in zig_xml:
        print("\nZig is failing to parse substitutions!")
        print("We need to fix the substitution parsing in Zig")
    elif zig_xml and "[Normal Substitution" in zig_xml:
        print("\nZig is outputting placeholder text instead of actual values!")
        print("We need to apply substitutions in template processing")
    
    # Save both outputs for detailed comparison
    with open("python_output.xml", "w") as f:
        f.write(python_xml)
    with open("zig_output.xml", "w") as f:
        f.write(zig_xml or "Failed")


if __name__ == "__main__":
    compare_results()