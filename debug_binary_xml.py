#!/usr/bin/env python

import Evtx.Evtx as evtx
import binascii
import hexdump

def main():
    with evtx.Evtx("tests/data/security.evtx") as log:
        # Get first record
        record = log.get_record(1)
        root = record.root()
        template = root.template()
        
        print(f"Template ID: {template.template_id()}")
        print(f"Template offset: {hex(template.absolute_offset(0x0))}")
        print(f"Template data length: {template.data_length()}")
        
        # Get the raw template data
        template_data_offset = template.absolute_offset(0x18)  # Data starts at +0x18
        template_data_length = template.data_length()
        
        print(f"Template data starts at: {hex(template_data_offset)}")
        print(f"Template data length: {template_data_length}")
        
        # Extract raw bytes
        raw_data = template._buf[template_data_offset:template_data_offset + min(template_data_length, 200)]
        print(f"First 200 bytes of template data:")
        print(hexdump.hexdump(raw_data, result='return'))
        
        # Look at the binary XML structure - let's examine tokens
        print("\nToken analysis:")
        for i in range(min(20, len(raw_data))):
            byte_val = raw_data[i]
            token = byte_val & 0x0F
            flags = byte_val >> 4
            print(f"Offset {i:02d}: 0x{byte_val:02x} -> token={token:02d} flags={flags:02d}")

if __name__ == "__main__":
    main()