#!/usr/bin/env python3
"""Debug script to investigate why no function pointer tables are found."""

import sys
import os
import base64
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ghidra_client import GhidraMCPClient
from src.config import GhidraMCPConfig

def main():
    c = GhidraMCPClient(GhidraMCPConfig())
    
    # Get functions and see the range
    funcs = c.list_functions()
    print(f'Total functions: {len(funcs)}')
    
    # Parse all functions
    function_map = {}
    for line in funcs:
        if ' at ' in line:
            parts = line.split(' at ')
            name = parts[0].strip()
            try:
                addr = int(parts[1].strip(), 16)
                function_map[addr] = name
            except:
                pass
    
    print(f'Parsed {len(function_map)} functions')
    if not function_map:
        print("No functions found!")
        return
    
    min_addr = min(function_map.keys())
    max_addr = max(function_map.keys())
    print(f'Function address range: 0x{min_addr:x} - 0x{max_addr:x}')
    
    # Print a few sample function addresses
    sample_addrs = list(function_map.keys())[:5]
    print("\nSample function addresses:")
    for addr in sample_addrs:
        print(f"  0x{addr:x} -> {function_map[addr]}")
    
    # Get segments
    print("\n=== SEGMENTS ===")
    segments = c.list_segments()
    for seg in segments:
        print(f"  {seg}")
    
    # Parse segments and scan ALL data segments for function pointers
    import re
    segments_to_scan = []
    for seg in segments:
        match = re.match(r'^([^:]+):\s*([0-9a-fA-F]+)\s*-\s*([0-9a-fA-F]+)', seg)
        if match:
            name = match.group(1).strip()
            start = int(match.group(2), 16)
            end = int(match.group(3), 16)
            # Skip code segment
            if name.lower() not in ['.text', 'headers', '.pdata', '.xdata', '.rsrc', '.reloc', '.gnu_debuglink']:
                segments_to_scan.append((name, start, end))
    
    print(f"\n=== Scanning {len(segments_to_scan)} data segments for function pointers ===")
    
    found_ptrs = []
    for seg_name, seg_start, seg_end in segments_to_scan:
        seg_size = seg_end - seg_start
        print(f"\nScanning {seg_name}: 0x{seg_start:x} - 0x{seg_end:x} ({seg_size} bytes)")
        
        scan_offset = 0
        while scan_offset < seg_size:
            addr = seg_start + scan_offset
            chunk_size = min(4096, seg_size - scan_offset)
            try:
                raw = c.read_bytes(hex(addr), length=chunk_size, format='raw')
                if 'Error' in raw or 'No program' in raw:
                    break
                
                data = base64.b64decode(raw.strip())
                
                # Parse as 8-byte pointers
                for i in range(0, len(data) - 7, 8):
                    ptr = struct.unpack('<Q', data[i:i+8])[0]
                    if min_addr <= ptr <= max_addr:
                        # Check if it's exactly a function address
                        if ptr in function_map:
                            found_ptrs.append((addr + i, ptr, function_map[ptr]))
                
                scan_offset += chunk_size
            except Exception as e:
                print(f"  Exception at 0x{addr:x}: {e}")
                break
        
        print(f"  Scanned {scan_offset} bytes, found {len(found_ptrs)} pointers so far")
    
    print(f"\nFound {len(found_ptrs)} potential function pointers in .rdata")
    
    if found_ptrs:
        print("\nFirst 20 function pointers found:")
        for faddr, ptr, name in found_ptrs[:20]:
            print(f"  0x{faddr:x} -> 0x{ptr:x} ({name})")
        
        # Check for consecutive pointers (tables)
        print("\n=== Looking for consecutive pointers (tables) ===")
        prev_addr = None
        consecutive_count = 0
        table_start = None
        tables = []
        
        for faddr, ptr, name in found_ptrs:
            if prev_addr is not None and faddr == prev_addr + 8:
                consecutive_count += 1
            else:
                if consecutive_count >= 2 and table_start is not None:
                    tables.append((table_start, consecutive_count + 1))
                consecutive_count = 0
                table_start = faddr
            prev_addr = faddr
        
        if consecutive_count >= 2 and table_start is not None:
            tables.append((table_start, consecutive_count + 1))
        
        if tables:
            print(f"Found {len(tables)} potential tables:")
            for taddr, count in tables:
                print(f"  Table at 0x{taddr:x} with {count} entries")
        else:
            print("No consecutive function pointers found (no tables)")
    else:
        print("No function pointers found in scanned region")
        print("\nLet's sample some raw data to see what's there:")
        raw = c.read_bytes(hex(rdata_start), length=128, format='hex')
        print(raw)

if __name__ == "__main__":
    main()

