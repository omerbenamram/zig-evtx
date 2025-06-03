#!/usr/bin/env python3
"""
Final understanding of the template structure issue
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from Evtx import Evtx as evtx
import Evtx.Nodes as e_nodes
import Evtx.Views as e_views

def final_analysis():
    """Final analysis to understand the complete template structure"""
    
    with evtx.Evtx("tests/data/security.evtx") as log:
        # Get record and show how Python parses the template
        record = log.get_record(1)
        root = record.root()
        
        print("=== PYTHON TEMPLATE PARSING ===")
        
        # Get the template through root
        template = root.template()
        print(f"Template ID: {template.template_id()}")
        print(f"Template offset: {template.offset()}")
        print(f"Template data length: {template.data_length()}")
        
        # Get the template children - this is where the parsing happens
        print("\n=== TEMPLATE CHILDREN (Binary XML nodes) ===")
        children = template.children()
        print(f"Number of children: {len(children)}")
        
        for i, child in enumerate(children[:10]):  # First 10 nodes
            print(f"\n[{i}] {type(child).__name__}")
            if hasattr(child, 'offset'):
                print(f"    Offset: {child.offset()}")
            if hasattr(child, 'length'):
                print(f"    Length: {child.length()}")
            if hasattr(child, 'token') and callable(child.token):
                print(f"    Token: 0x{child.token():02x}")
            if isinstance(child, e_nodes.OpenStartElementNode):
                print(f"    Tag name: {child.tag_name()}")
                print(f"    String offset: {child.string_offset()}")
                print(f"    Tag length: {child.tag_length()}")
                print(f"    Has children: {len(child.children())}")
                # Show first few child nodes
                for j, subchild in enumerate(child.children()[:3]):
                    print(f"      [{j}] {type(subchild).__name__}")
        
        # Now show the template format
        print("\n=== TEMPLATE FORMAT (readable view) ===")
        template_format = e_views.evtx_template_readable_view(root)
        print(f"Format length: {len(template_format)}")
        print("First 500 chars:")
        print(template_format[:500])
        
        # The key insight: The template parsing continues THROUGH the binary XML
        # It doesn't stop at EndOfStream because templates can contain multiple streams!
        
        print("\n=== KEY INSIGHT ===")
        print("The template contains NESTED binary XML structures!")
        print("The parser must continue past EndOfStream tokens to parse the complete template.")
        
        # Let's trace the full parsing
        print("\n=== FULL TEMPLATE STRUCTURE ===")
        def show_node_tree(node, depth=0):
            indent = "  " * depth
            node_type = type(node).__name__
            print(f"{indent}{node_type}", end="")
            
            if isinstance(node, e_nodes.OpenStartElementNode):
                print(f" <{node.tag_name()}>")
                for child in node.children():
                    show_node_tree(child, depth + 1)
            elif isinstance(node, e_nodes.AttributeNode):
                print(f" {node.attribute_name().string()}=", end="")
                show_node_tree(node.attribute_value(), depth)
            elif isinstance(node, (e_nodes.NormalSubstitutionNode, e_nodes.ConditionalSubstitutionNode)):
                print(f" [index={node.index()}, type={node.type()}]")
            else:
                print()
        
        print("\nTemplate structure:")
        for child in template.children()[:3]:  # Just first few to avoid too much output
            show_node_tree(child)

if __name__ == "__main__":
    final_analysis()