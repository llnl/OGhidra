#!/usr/bin/env python3
"""
Test script for the scan_function_pointer_tables smart tool.

This tool scans the binary for function pointer tables (vtables, dispatch tables)
without requiring LLM intervention - it runs algorithmically.

Prerequisites:
1. Ghidra must be running with OGhidraMCP plugin loaded
2. A binary must be open in Ghidra

Usage:
    python tests/test_scan_function_pointer_tables.py
"""

import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ghidra_client import GhidraMCPClient
from src.config import GhidraMCPConfig


def main():
    print("=" * 60)
    print("Testing scan_function_pointer_tables Smart Tool")
    print("=" * 60)
    
    # Initialize the client
    config = GhidraMCPConfig()
    client = GhidraMCPClient(config)
    
    # Test 1: Check connection
    print("\n[1] Testing connection to GhidraMCP...")
    health = client.health_check()
    if not health:
        print(f"    FAILED: Could not connect to GhidraMCP")
        print("    Make sure Ghidra is running with the OGhidraMCP plugin loaded.")
        return 1
    print(f"    OK: Connected to GhidraMCP")
    
    # Test 2: Get function count
    print("\n[2] Getting function list...")
    functions = client.list_functions()
    if not functions or "Error" in functions[0]:
        print(f"    FAILED: Could not get functions: {functions}")
        return 1
    print(f"    OK: Found {len(functions)} functions")
    
    # Test 3: Run the scan with default parameters
    print("\n[3] Running scan_function_pointer_tables (default params)...")
    print("    This may take a moment...")
    
    try:
        tables = client.scan_function_pointer_tables()
        
        if tables:
            print(f"    OK: Found {len(tables)} potential function pointer table(s)")
            
            # Print formatted results
            print("\n" + "-" * 60)
            formatted = client.format_table_scan_results(tables)
            print(formatted)
            print("-" * 60)
        else:
            print("    OK: No function pointer tables detected (this may be normal for some binaries)")
            
    except Exception as e:
        print(f"    FAILED: Error during scan: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Test 4: Run with custom parameters (smaller scan for speed)
    print("\n[4] Running scan with custom parameters...")
    print("    (min_table_entries=2, pointer_size=8, max_scan_size=16384)")
    
    try:
        tables_custom = client.scan_function_pointer_tables(
            min_table_entries=2,
            pointer_size=8,
            max_scan_size=16384
        )
        print(f"    OK: Found {len(tables_custom)} table(s) with looser criteria")
        
    except Exception as e:
        print(f"    FAILED: Error during custom scan: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Test 5: Verify read_bytes is working (prerequisite for table scanning)
    print("\n[5] Testing read_bytes (used internally by scanner)...")
    if functions and " at " in functions[0]:
        # Get the first function address
        addr = functions[0].split(" at ")[1].strip()
        try:
            bytes_result = client.read_bytes(addr, length=32, format="hex")
            if bytes_result and "Error" not in bytes_result:
                print(f"    OK: Successfully read 32 bytes at {addr}")
                print(f"    Sample: {bytes_result[:80]}...")
            else:
                print(f"    WARNING: read_bytes returned: {bytes_result}")
        except Exception as e:
            print(f"    WARNING: read_bytes failed: {e}")
    
    print("\n" + "=" * 60)
    print("All tests completed successfully!")
    print("=" * 60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

