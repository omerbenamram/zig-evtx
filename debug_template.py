#!/usr/bin/env python

import Evtx.Evtx as evtx
import Evtx.Views as e_views

def main():
    with evtx.Evtx("tests/data/security.evtx") as log:
        # Get first record
        record = log.get_record(1)
        if record is None:
            print("Record 1 not found")
            return
            
        # Get its root node
        root = record.root()
        
        # Get template instance and template ID
        template_instance = root.template_instance()
        template_id = template_instance.template_id()
        print(f"Record 1 uses template ID: {template_id}")
        
        # Get the template
        template = root.template()
        print(f"Template ID: {template.template_id()}")
        print(f"Template GUID: {template.guid()}")
        print(f"Template data length: {template.data_length()}")
        
        # Get template format (readable view)
        template_format = e_views.evtx_template_readable_view(root)
        print(f"Template format:\n{template_format}")
        
        # Get actual XML
        xml_output = record.xml()
        print(f"Actual XML:\n{xml_output}")
        
        # Get substitutions
        substitutions = root.substitutions()
        print(f"Number of substitutions: {len(substitutions)}")
        for i, sub in enumerate(substitutions):
            print(f"  Substitution {i}: {type(sub).__name__} = '{sub.string()}'")

if __name__ == "__main__":
    main()