#!/usr/bin/env python

import Evtx.Evtx as evtx
import hexdump
import Evtx.Nodes as e_nodes

def analyze_binary_xml_tokens(data, max_bytes=200):
    """Analyze the token stream in binary XML data"""
    print(f"Analyzing {len(data)} bytes of binary XML data:")
    print(hexdump.hexdump(data[:max_bytes], result='return'))
    
    print("\nToken-by-token analysis:")
    pos = 0
    while pos < min(len(data), max_bytes):
        if pos >= len(data):
            break
            
        token_byte = data[pos]
        token = token_byte & 0x0F
        flags = token_byte >> 4
        
        token_names = {
            0x00: "EndOfStream",
            0x01: "OpenStartElement", 
            0x02: "CloseStartElement",
            0x03: "CloseEmptyElement",
            0x04: "CloseElement",
            0x05: "Value",
            0x06: "Attribute",
            0x07: "CDataSection",
            0x08: "EntityReference",
            0x09: "CharRef",
            0x0A: "ProcessingInstructionTarget",
            0x0B: "ProcessingInstructionData", 
            0x0C: "TemplateInstance",
            0x0D: "NormalSubstitution",
            0x0E: "ConditionalSubstitution",
            0x0F: "StartOfStream"
        }
        
        token_name = token_names.get(token, f"Unknown({token})")
        print(f"  Pos {pos:03d}: 0x{token_byte:02x} -> {token_name} (token={token}, flags={flags})")
        
        # Try to advance position based on token type
        if token == 0x00:  # EndOfStream
            pos += 1
            break
        elif token == 0x0F:  # StartOfStream
            pos += 4  # StartOfStream has 4 bytes
        elif token == 0x01:  # OpenStartElement
            pos += 1  # Just advance by token byte for now
            # This would need proper parsing to get actual length
        else:
            pos += 1  # Safe increment
            
        if pos > 50:  # Limit analysis
            print("  ... (truncated)")
            break

def main():
    with evtx.Evtx("tests/data/security.evtx") as log:
        # Get first record
        record = log.get_record(1)
        root = record.root()
        template = root.template()
        
        print(f"=== TEMPLATE 3346188909 ANALYSIS ===")
        print(f"Template ID: {template.template_id()}")
        print(f"Template GUID: {template.guid()}")
        print(f"Template absolute offset: {hex(template.absolute_offset(0x0))}")
        print(f"Template data length: {template.data_length()}")
        
        # Get template data starting offset
        template_data_offset = template.absolute_offset(0x18)  # Data starts at +0x18
        print(f"Template data starts at: {hex(template_data_offset)}")
        
        # Extract the binary XML data
        binary_xml_data = template._buf[template_data_offset:template_data_offset + template.data_length()]
        
        print(f"\n=== BINARY XML DATA ANALYSIS ===")
        analyze_binary_xml_tokens(binary_xml_data)
        
        print(f"\n=== PYTHON PARSER RESULT ===")
        # Show what Python produces
        template_xml = template.template_format()
        print(f"Template format length: {len(template_xml)}")
        print(f"Template format:\n{template_xml}")
        
        print(f"\n=== PYTHON TEMPLATE STRUCTURE ===")
        # Try to understand how Python parses this
        try:
            # Get the template's children to see the structure
            for i, child in enumerate(template.children()):
                print(f"Child {i}: {type(child).__name__}")
                if hasattr(child, 'tag_name'):
                    try:
                        print(f"  Tag name: {child.tag_name()}")
                    except:
                        print(f"  Tag name: <error>")
        except Exception as e:
            print(f"Error analyzing template children: {e}")

if __name__ == "__main__":
    main()