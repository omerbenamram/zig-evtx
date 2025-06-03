#!/usr/bin/env python3
"""
Debug template parsing at offset 550 (template ID 3346188909)
"""

import Evtx.Evtx as evtx
import struct

with evtx.Evtx("tests/data/security.evtx") as fh:
    # Get first chunk
    chunk = next(fh.chunks())

    # Read data at offset 550
    chunk_offset = chunk._offset
    template_offset = 550  # This is relative to chunk start

    print(f"Chunk offset: 0x{chunk_offset:x}")
    print(f"Template offset (relative): 0x{template_offset:x}")

    # Access the chunk buffer directly
    chunk_data = chunk._buf

    # Read template header at offset 550
    data = chunk_data[template_offset : template_offset + 64]

    print("\nTemplate header bytes at offset 550:")
    for i in range(0, min(64, len(data)), 16):
        hex_str = " ".join(f"{b:02x}" for b in data[i : i + 16])
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i : i + 16])
        print(f"{i:04x}: {hex_str:<48} {ascii_str}")

    # Parse as template definition header
    if len(data) >= 24:
        print("\nParsing as Template definition:")
        next_template_offset = struct.unpack("<I", data[0:4])[0]
        template_id = struct.unpack("<I", data[4:8])[0]
        guid = data[8:24]
        data_length = struct.unpack("<I", data[24:28])[0] if len(data) >= 28 else 0

        print(f"Next template offset: 0x{next_template_offset:x}")
        print(f"Template ID: {template_id} (0x{template_id:08x})")
        print(f"GUID: {guid.hex()}")
        print(f"Data length: {data_length}")

        # The template data starts after the header (at offset 550 + 28)
        if data_length > 0 and len(chunk_data) > template_offset + 28:
            template_data_start = template_offset + 28
            template_data = chunk_data[template_data_start : template_data_start + min(64, data_length)]

            print(f"\nTemplate data (starting at offset {template_data_start}):")
            for i in range(0, min(64, len(template_data)), 16):
                hex_str = " ".join(f"{b:02x}" for b in template_data[i : i + 16])
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in template_data[i : i + 16])
                print(f"{i:04x}: {hex_str:<48} {ascii_str}")

            # Check first token
            if len(template_data) > 0:
                first_token = template_data[0]
                print(f"\nFirst token in template data: 0x{first_token:02x}")
                if first_token == 0x0F:
                    print("StartOfStream token - this is a binary XML template")
