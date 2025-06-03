#!/usr/bin/env python3
"""
Find the actual location of template 3346188909
"""

import Evtx.Evtx as evtx
import struct

target_id = 3346188909

with evtx.Evtx("tests/data/security.evtx") as fh:
    # Search all chunks
    for chunk_idx, chunk in enumerate(fh.chunks()):
        chunk_offset = chunk._offset
        print(f"\nChunk {chunk_idx} at offset 0x{chunk_offset:x}")

        # Get all templates in this chunk
        templates = chunk.templates()
        for tid, template in templates.items():
            if tid == target_id:
                print(f"\nFOUND Template {tid} (0x{tid:08x})!")
                print(f"Template object offset: 0x{template._offset:x}")
                print(f"Chunk-relative offset: 0x{template._offset - chunk_offset:x}")
                print(f"Template data length: {template._length}")

                # Get the actual template definition location
                # The template offset in the chunk header points to the template definition
                chunk_data = chunk._buf

                # Search for template definitions in the chunk
                # Template definitions start with: next_offset (4), template_id (4), guid (16), data_length (4)
                offset = 0x200  # Templates typically start after chunk header
                while offset + 28 < len(chunk_data):
                    next_offset = struct.unpack("<I", chunk_data[offset : offset + 4])[0]
                    template_id = struct.unpack("<I", chunk_data[offset + 4 : offset + 8])[0]

                    if template_id == target_id:
                        print(f"\nFound template definition at chunk offset 0x{offset:x}")
                        print(f"Next template offset: 0x{next_offset:x}")

                        # Show the template header
                        header_data = chunk_data[offset : offset + 64]
                        print("\nTemplate header:")
                        for i in range(0, min(64, len(header_data)), 16):
                            hex_str = " ".join(f"{b:02x}" for b in header_data[i : i + 16])
                            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in header_data[i : i + 16])
                            print(f"{i:04x}: {hex_str:<48} {ascii_str}")
                        break

                    # Move to next template
                    if next_offset == 0:
                        break
                    offset = next_offset
