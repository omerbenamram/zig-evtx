#!/usr/bin/env python3
"""
Debug template format generation - shows how binary XML becomes template format
"""

import sys
import os
import re

sys.path.insert(0, os.path.dirname(__file__))

from Evtx import Evtx as evtx
import Evtx.Views as e_views
import Evtx.Nodes as e_nodes

def analyze_template_format():
    """Show how template format is generated from binary XML"""
    
    with evtx.Evtx("tests/data/security.evtx") as log:
        # Get first record
        record = next(log.records())
        root = record.root()
        
        print("=== TEMPLATE FORMAT ANALYSIS ===")
        
        # Show the direct rendering path
        print("\n1. DIRECT RENDERING PATH (Views.render_root_node):")
        
        # Get substitutions
        subs = root.substitutions()
        print(f"   Substitution count: {len(subs)}")
        
        # Get template through root node
        template = root.template()
        print(f"   Template ID: {template.template_id()}")
        print(f"   Template offset: {template.offset()}")
        
        # Show template children (binary XML nodes)
        print(f"\n   Template children (binary XML nodes):")
        for i, child in enumerate(template.children()[:5]):  # First 5 nodes
            print(f"   [{i}] {type(child).__name__}")
            if hasattr(child, 'token'):
                print(f"       Token: 0x{child.token():02x}")
        
        # Now show the rendering process
        print(f"\n2. TEMPLATE RENDERING PROCESS:")
        
        # The magic happens in Views.render_root_node_with_subs
        print("   Using Views.render_root_node_with_subs()...")
        
        # Let's manually trace through the rendering
        def trace_render(node, depth=0):
            indent = "   " * depth
            node_type = type(node).__name__
            
            if isinstance(node, e_nodes.OpenStartElementNode):
                print(f"{indent}<{node.tag_name()}>")
                for child in node.children():
                    trace_render(child, depth + 1)
            elif isinstance(node, e_nodes.NormalSubstitutionNode):
                print(f"{indent}[Normal Sub: index={node.index()}, type={node.type()}]")
            elif isinstance(node, e_nodes.ConditionalSubstitutionNode):
                print(f"{indent}[Conditional Sub: index={node.index()}, type={node.type()}]")
            elif isinstance(node, e_nodes.AttributeNode):
                name = node.attribute_name().string()
                print(f"{indent}@{name}=", end="")
                trace_render(node.attribute_value(), 0)
            else:
                print(f"{indent}{node_type}")
        
        print("\n   Template structure trace:")
        for child in template.children()[:3]:  # Trace first few nodes
            trace_render(child, 2)
        
        # Show the final XML generation
        print(f"\n3. FINAL XML GENERATION:")
        xml = record.xml()
        print(f"   XML length: {len(xml)}")
        print(f"   XML preview: {xml[:200]}...")
        
        # Show how Python formats substitutions
        print(f"\n4. SUBSTITUTION FORMAT CONVERSION:")
        print("   Python converts substitution markers to format placeholders:")
        print('   "[Normal Substitution(index=0, type=4)]" → "{0:}"')
        print('   "[Conditional Substitution(index=14, type=1)]" → "{14:}"')
        
        # The actual regex used
        matcher = r"\[(?:Normal|Conditional) Substitution\(index=(\d+), type=\d+\)\]"
        example = "[Conditional Substitution(index=14, type=1)]"
        result = re.sub(matcher, "{\\1:}", example)
        print(f'\n   Example: "{example}" → "{result}"')

if __name__ == "__main__":
    analyze_template_format()