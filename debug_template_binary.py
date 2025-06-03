#!/usr/bin/env python3
"""
Debug the binary structure step by step
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from Evtx import Evtx as evtx
import Evtx.Nodes as e_nodes

def analyze_binary_structure():
    """Analyze the binary structure carefully"""
    
    with evtx.Evtx("tests/data/security.evtx") as log:
        chunk = next(log.chunks())
        
        # Don't load strings/templates yet - do it manually
        print("=== CHUNK ANALYSIS ===")
        print(f"Chunk offset: 0x{chunk._offset:x}")
        
        # Check string table manually
        print("\n=== STRING TABLE (first 10 entries) ===")
        for i in range(10):
            offset = chunk.unpack_dword(0x80 + (i * 4))
            if offset > 0:
                print(f"Slot {i}: offset = {offset} (0x{offset:x})")
        
        # Now check template table
        print("\n=== TEMPLATE TABLE (slots with data) ===")
        for i in range(32):
            offset = chunk.unpack_dword(0x180 + (i * 4))
            if offset > 0:
                print(f"Slot {i}: offset = {offset} (0x{offset:x})")
                # Check template marker
                if offset >= 10:
                    token = chunk.unpack_byte(offset - 10)
                    print(f"  Token at -10: 0x{token:02x} (should be 0x0C)")
        
        # Now focus on template at offset 550
        print("\n=== TEMPLATE AT OFFSET 550 ===")
        template_offset = 550
        
        # Read template header
        next_offset = chunk.unpack_dword(template_offset)
        template_id = chunk.unpack_dword(template_offset + 4)
        data_length = chunk.unpack_dword(template_offset + 0x14)
        
        print(f"Next offset: {next_offset}")
        print(f"Template ID: {template_id}")
        print(f"Data length: {data_length}")
        
        # Show binary XML data
        data_start = template_offset + 0x18
        print(f"\nBinary XML starts at chunk offset: {data_start}")
        
        # Show first 64 bytes in detail
        print("\nFirst 64 bytes of binary XML:")
        for i in range(0, 64, 16):
            data = chunk._buf[chunk._offset + data_start + i:chunk._offset + data_start + i + 16]
            hex_str = ' '.join(f'{b:02x}' for b in data)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
            print(f"  {i:04x}: {hex_str:<48} {ascii_str}")
        
        # Now parse token by token with correct understanding
        print("\n=== TOKEN BY TOKEN PARSING ===")
        pos = data_start
        
        # Token 0: StartOfStream
        token0 = chunk.unpack_byte(pos)
        print(f"\nToken 0 at offset {pos}: 0x{token0:02x} = StartOfStream")
        pos += 1
        
        # Token 1: OpenStartElement 
        token1 = chunk.unpack_byte(pos)
        print(f"\nToken 1 at offset {pos}: 0x{token1:02x} = OpenStartElement")
        pos += 1
        
        # Now the OpenStartElement data
        print("OpenStartElement data:")
        
        # Check what Python actually reads
        print("\nPython's interpretation:")
        # Create a minimal node to see field offsets
        class TestNode:
            def __init__(self, chunk, offset):
                self._buf = chunk._buf
                self._offset = chunk._offset + offset
                self._implicit_offset = 0
                
            def declare_field(self, type, name, offset=None):
                if offset is None:
                    offset = self._implicit_offset
                print(f"  {name}: offset={offset}, type={type}")
                
                # Update implicit offset
                if type == "byte":
                    self._implicit_offset = offset + 1
                elif type == "word":
                    self._implicit_offset = offset + 2
                elif type == "dword":
                    self._implicit_offset = offset + 4
        
        node = TestNode(chunk, pos)
        node.declare_field("byte", "token", 0x0)
        node.declare_field("word", "unknown0")
        node.declare_field("dword", "size")
        node.declare_field("dword", "string_offset")
        
        # Show actual values
        print("\nActual values at those offsets:")
        print(f"  token: 0x{chunk.unpack_byte(pos):02x}")
        print(f"  unknown0: 0x{chunk.unpack_word(pos + 1):04x}")
        print(f"  size: {chunk.unpack_dword(pos + 3)}")
        print(f"  string_offset: {chunk.unpack_dword(pos + 7)}")
        
        # The issue is clear - we're reading from wrong offsets!
        # Token was already consumed, so offsets should be:
        print("\nCorrected offsets (token already consumed):")
        print(f"  unknown0: 0x{chunk.unpack_word(pos):04x}")
        print(f"  size: {chunk.unpack_dword(pos + 2)}")
        print(f"  string_offset: {chunk.unpack_dword(pos + 6)}")

if __name__ == "__main__":
    analyze_binary_structure()