#!/usr/bin/env python3
"""
Extract and hexdump raw BinXML bytes from a specific EVTX record.

Usage:
    python scripts/record_hexdump.py samples/issue_201.evtx --index 1
    python scripts/record_hexdump.py samples/issue_201.evtx --rid 3229
"""

import argparse
import struct
import sys
from pathlib import Path


# EVTX Constants
FILE_HEADER_SIZE = 4096
CHUNK_SIZE = 65536
CHUNK_HEADER_SIZE = 512
RECORD_MAGIC = b"\x2a\x2a\x00\x00"


def read_file_header(data: bytes) -> dict:
    """Parse EVTX file header."""
    if not data.startswith(b"ElfFile\x00"):
        raise ValueError("Invalid EVTX file signature")
    
    return {
        "signature": data[0:8],
        "first_chunk": struct.unpack_from("<Q", data, 8)[0],
        "last_chunk": struct.unpack_from("<Q", data, 16)[0],
        "next_record_id": struct.unpack_from("<Q", data, 24)[0],
        "header_size": struct.unpack_from("<I", data, 32)[0],
        "minor_version": struct.unpack_from("<H", data, 36)[0],
        "major_version": struct.unpack_from("<H", data, 38)[0],
        "header_block_size": struct.unpack_from("<H", data, 40)[0],
        "num_chunks": struct.unpack_from("<H", data, 42)[0],
    }


def read_chunk_header(chunk_data: bytes) -> dict:
    """Parse chunk header."""
    if not chunk_data.startswith(b"ElfChnk\x00"):
        raise ValueError("Invalid chunk signature")
    
    return {
        "signature": chunk_data[0:8],
        "first_event_record_number": struct.unpack_from("<Q", chunk_data, 8)[0],
        "last_event_record_number": struct.unpack_from("<Q", chunk_data, 16)[0],
        "first_event_record_id": struct.unpack_from("<Q", chunk_data, 24)[0],
        "last_event_record_id": struct.unpack_from("<Q", chunk_data, 32)[0],
        "header_size": struct.unpack_from("<I", chunk_data, 40)[0],
        "last_event_record_offset": struct.unpack_from("<I", chunk_data, 44)[0],
        "free_space_offset": struct.unpack_from("<I", chunk_data, 48)[0],
    }


def iter_records(chunk_data: bytes, chunk_index: int):
    """Iterate over records in a chunk."""
    header = read_chunk_header(chunk_data)
    offset = CHUNK_HEADER_SIZE
    
    while offset < header["free_space_offset"] and offset + 8 < len(chunk_data):
        # Check for record magic
        if chunk_data[offset:offset+4] != RECORD_MAGIC:
            break
        
        size = struct.unpack_from("<I", chunk_data, offset + 4)[0]
        if size < 32 or offset + size > len(chunk_data):
            break
        
        record_id = struct.unpack_from("<Q", chunk_data, offset + 8)[0]
        timestamp = struct.unpack_from("<Q", chunk_data, offset + 16)[0]
        
        # BinXML starts at offset 24, ends 4 bytes before record end
        binxml_start = offset + 24
        binxml_end = offset + size - 4
        binxml_data = chunk_data[binxml_start:binxml_end]
        
        yield {
            "chunk_index": chunk_index,
            "chunk_offset": offset,
            "file_offset": FILE_HEADER_SIZE + chunk_index * CHUNK_SIZE + offset,
            "size": size,
            "record_id": record_id,
            "timestamp": timestamp,
            "binxml_offset": binxml_start,
            "binxml_data": binxml_data,
        }
        
        offset += size


def hexdump(data: bytes, start_offset: int = 0, width: int = 16) -> str:
    """Generate a hex dump with offsets and ASCII representation."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{start_offset + i:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def annotate_binxml(data: bytes) -> list:
    """Provide annotations for known BinXML structures."""
    annotations = []
    if len(data) == 0:
        return annotations
    
    pos = 0
    
    # Check for fragment header
    if data[0] == 0x0f:
        annotations.append((0, 4, "FragmentHeader", f"token=0x{data[0]:02x} major={data[1]} minor={data[2]} flags={data[3]}"))
        pos = 4
    
    if pos < len(data):
        token = data[pos]
        base_token = token & 0x1f
        has_more = (token & 0x40) != 0
        
        token_names = {
            0x01: "TOK_OPEN_START",
            0x02: "TOK_CLOSE_START",
            0x03: "TOK_CLOSE_EMPTY",
            0x04: "TOK_END_ELEMENT",
            0x05: "TOK_VALUE",
            0x06: "TOK_ATTRIBUTE",
            0x07: "TOK_CDATA",
            0x08: "TOK_CHARREF",
            0x09: "TOK_ENTITYREF",
            0x0a: "TOK_PITARGET",
            0x0b: "TOK_PIDATA",
            0x0c: "TOK_TEMPLATE_INSTANCE",
            0x0d: "TOK_NORMAL_SUBST",
            0x0e: "TOK_OPTIONAL_SUBST",
            0x0f: "TOK_FRAGMENT_HEADER",
        }
        
        token_name = token_names.get(base_token, f"UNKNOWN(0x{base_token:02x})")
        flags = f" +hasMore" if has_more else ""
        annotations.append((pos, 1, "Token", f"{token_name}{flags} (0x{token:02x})"))
        
        # For template instance, show more detail
        if base_token == 0x0c and pos + 10 <= len(data):
            # TemplateInstanceStart: u8 token, u8 unknown, u32 def_data_off, u32 instance_data_off
            unknown = data[pos + 1]
            def_off = struct.unpack_from("<I", data, pos + 2)[0]
            inst_off = struct.unpack_from("<I", data, pos + 6)[0]
            annotations.append((pos, 10, "TemplateInstanceStart", 
                f"unknown={unknown} def_off=0x{def_off:x} inst_off=0x{inst_off:x}"))
        
        # For open start, show element header
        elif base_token == 0x01 and pos + 11 <= len(data):
            # After token: u16 dep_id, u32 data_size, u32 name_offset
            dep_id = struct.unpack_from("<H", data, pos + 1)[0]
            data_size = struct.unpack_from("<I", data, pos + 3)[0]
            name_off = struct.unpack_from("<I", data, pos + 7)[0]
            annotations.append((pos + 1, 10, "ElementHeader", 
                f"dep_id={dep_id} data_size=0x{data_size:x} name_off=0x{name_off:x}"))
    
    return annotations


def main():
    parser = argparse.ArgumentParser(description="Extract and hexdump EVTX record BinXML")
    parser.add_argument("evtx_file", help="Path to EVTX file")
    parser.add_argument("--index", "-n", type=int, help="1-based record index")
    parser.add_argument("--rid", type=int, help="EventRecordID to find")
    parser.add_argument("--all", action="store_true", help="List all records (summary only)")
    parser.add_argument("--limit", type=int, default=512, help="Max bytes to dump (default: 512)")
    args = parser.parse_args()
    
    if not args.index and not args.rid and not args.all:
        parser.error("Specify --index, --rid, or --all")
    
    path = Path(args.evtx_file)
    data = path.read_bytes()
    
    file_header = read_file_header(data)
    print(f"File: {path.name}")
    print(f"Chunks: {file_header['num_chunks']}")
    print()
    
    # Collect all records
    all_records = []
    for chunk_idx in range(file_header["num_chunks"]):
        chunk_start = FILE_HEADER_SIZE + chunk_idx * CHUNK_SIZE
        chunk_end = chunk_start + CHUNK_SIZE
        if chunk_end > len(data):
            break
        chunk_data = data[chunk_start:chunk_end]
        
        try:
            for rec in iter_records(chunk_data, chunk_idx):
                all_records.append(rec)
        except Exception as e:
            print(f"Warning: Error reading chunk {chunk_idx}: {e}", file=sys.stderr)
    
    print(f"Total records: {len(all_records)}")
    print()
    
    if args.all:
        print("Index  RecordID  ChunkOff  FileOff   Size    BinXML Len  First Bytes")
        print("-" * 80)
        for i, rec in enumerate(all_records, 1):
            first_bytes = rec["binxml_data"][:8].hex() if rec["binxml_data"] else ""
            print(f"{i:5}  {rec['record_id']:8}  0x{rec['chunk_offset']:04x}    0x{rec['file_offset']:06x}  {rec['size']:6}  {len(rec['binxml_data']):10}  {first_bytes}")
        return
    
    # Find specific record
    target_rec = None
    if args.rid:
        for rec in all_records:
            if rec["record_id"] == args.rid:
                target_rec = rec
                break
        if not target_rec:
            print(f"Record ID {args.rid} not found", file=sys.stderr)
            sys.exit(1)
    else:
        idx = args.index - 1
        if idx < 0 or idx >= len(all_records):
            print(f"Index {args.index} out of range (1-{len(all_records)})", file=sys.stderr)
            sys.exit(1)
        target_rec = all_records[idx]
    
    # Print record info
    print(f"Record ID: {target_rec['record_id']}")
    print(f"Chunk: {target_rec['chunk_index']}")
    print(f"Chunk offset: 0x{target_rec['chunk_offset']:x}")
    print(f"File offset: 0x{target_rec['file_offset']:x}")
    print(f"Record size: {target_rec['size']} bytes")
    print(f"BinXML size: {len(target_rec['binxml_data'])} bytes")
    print()
    
    # Annotations
    annotations = annotate_binxml(target_rec["binxml_data"])
    if annotations:
        print("=== BinXML Annotations ===")
        for off, size, name, desc in annotations:
            print(f"  0x{off:04x} ({size:2} bytes): {name} - {desc}")
        print()
    
    # Hex dump
    dump_data = target_rec["binxml_data"][:args.limit]
    print(f"=== BinXML Hex Dump (first {len(dump_data)} of {len(target_rec['binxml_data'])} bytes) ===")
    print(hexdump(dump_data))
    
    if len(target_rec["binxml_data"]) > args.limit:
        print(f"\n... {len(target_rec['binxml_data']) - args.limit} more bytes ...")


if __name__ == "__main__":
    main()

