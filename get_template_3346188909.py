#!/usr/bin/env python3
import Evtx.Evtx as evtx
from Evtx.BinaryParser import memoize
from Evtx.BinaryParser import hex_dump

with evtx.Evtx("tests/data/security.evtx") as fh:
    for chunk in fh.chunks():
        for template in chunk.templates().values():
            if template.template_id() == 3346188909:
                print(f"Template {template.template_id()} at offset {template._offset}")
                print(f"Template data length: {template._length}")

                # Get the XML by parsing template with no substitutions
                xml = evtx.evtx_template_readable_xml(template, {})
                print(f"Template XML length: {len(xml)}")
                print("Template XML:")
                print(xml)

                # Also print first few bytes of raw template data
                print("\nFirst 32 bytes of template data:")
                print(hex_dump(template._buf[template._offset : template._offset + 32]))

                exit(0)

print("Template 3346188909 not found")
