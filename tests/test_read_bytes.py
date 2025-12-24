"""
Test script for the read_bytes capability added to the NewMCP plugin.

This script tests the AI's ability to read raw bytes from memory addresses
in the currently loaded Ghidra program.

Prerequisites:
- Ghidra must be running with the NewMCP plugin installed
- A binary must be loaded in Ghidra
- The GhidraMCP HTTP server must be active (default: http://127.0.0.1:8080)

Usage:
    python tests/test_read_bytes.py
"""

import sys
import os

# Add project root to path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.ghidra_client import GhidraMCPClient
from src.config import GhidraMCPConfig


def test_read_bytes_hex_format():
    """Test reading bytes in hex dump format."""
    print("\n" + "="*60)
    print("TEST: read_bytes (hex format)")
    print("="*60)
    
    config = GhidraMCPConfig()
    client = GhidraMCPClient(config)
    
    # Test address from user's function: FUN_10040fae0
    # First bytes should be: 55 57 56 53 48 83 ec 58 (PUSH RBP, PUSH RDI, etc.)
    test_address = "10040fae0"
    
    print(f"\nReading 64 bytes from address 0x{test_address}...")
    result = client.read_bytes(test_address, length=64, format="hex")
    
    print("\nResult:")
    print("-" * 50)
    print(result)
    print("-" * 50)
    
    # Verify we got a response
    if "Error" in result or "No program" in result:
        print(f"\n[FAIL] Error reading bytes: {result}")
        return False
    
    # Check for expected bytes (function prologue)
    # 55 = PUSH RBP, 57 = PUSH RDI, 56 = PUSH RSI, 53 = PUSH RBX
    expected_start = "55 57 56 53"
    if expected_start.upper() in result.upper():
        print(f"\n[PASS] Found expected prologue bytes: {expected_start}")
        return True
    else:
        print(f"\n[INFO] Did not find expected bytes '{expected_start}' - may be different binary")
        print("[INFO] Checking if we got valid hex dump format...")
        # Check if we at least got a valid hex dump format
        if ":" in result and "|" in result:
            print("[PASS] Valid hex dump format received")
            return True
        return False


def test_read_bytes_raw_format():
    """Test reading bytes in base64 raw format."""
    print("\n" + "="*60)
    print("TEST: read_bytes (raw/base64 format)")
    print("="*60)
    
    config = GhidraMCPConfig()
    client = GhidraMCPClient(config)
    
    test_address = "10040fae0"
    
    print(f"\nReading 16 bytes from address 0x{test_address} in raw format...")
    result = client.read_bytes(test_address, length=16, format="raw")
    
    print("\nResult (base64):")
    print("-" * 50)
    print(result)
    print("-" * 50)
    
    if "Error" in result or "No program" in result:
        print(f"\n[FAIL] Error reading bytes: {result}")
        return False
    
    # Try to decode the base64
    import base64
    try:
        decoded = base64.b64decode(result)
        print(f"\n[PASS] Successfully decoded {len(decoded)} bytes from base64")
        print(f"Raw bytes (hex): {decoded.hex()}")
        return True
    except Exception as e:
        print(f"\n[FAIL] Could not decode base64: {e}")
        return False


def test_read_bytes_multiple_addresses():
    """Test reading from multiple addresses in the function."""
    print("\n" + "="*60)
    print("TEST: read_bytes from multiple function addresses")
    print("="*60)
    
    config = GhidraMCPConfig()
    client = GhidraMCPClient(config)
    
    # Test several addresses from the function disassembly
    test_cases = [
        ("10040fae0", "Function entry (PUSH RBP)"),
        ("10040fae8", "MOV RDI instruction"),
        ("10040faef", "MOV RSI instruction"),
        ("10040fb02", "JZ instruction"),
    ]
    
    all_passed = True
    for address, description in test_cases:
        print(f"\n--- {description} @ 0x{address} ---")
        result = client.read_bytes(address, length=8, format="hex")
        
        if "Error" in result or not result.strip():
            print(f"[FAIL] Could not read from 0x{address}")
            all_passed = False
        else:
            # Just show first line of hex dump
            first_line = result.split('\n')[0] if result else "(empty)"
            print(f"[OK] {first_line}")
    
    return all_passed


def test_read_bytes_boundary_conditions():
    """Test edge cases and boundary conditions."""
    print("\n" + "="*60)
    print("TEST: read_bytes boundary conditions")
    print("="*60)
    
    config = GhidraMCPConfig()
    client = GhidraMCPClient(config)
    
    test_cases = [
        ("10040fae0", 1, "Minimum length (1 byte)"),
        ("10040fae0", 256, "Medium length (256 bytes)"),
        ("10040fae0", 4096, "Maximum length (4096 bytes)"),
    ]
    
    all_passed = True
    for address, length, description in test_cases:
        print(f"\n--- {description} ---")
        result = client.read_bytes(address, length=length, format="hex")
        
        if "Error" in result:
            if "Length must be" in result and length > 4096:
                print(f"[PASS] Correctly rejected length > 4096")
            else:
                print(f"[FAIL] {result}")
                all_passed = False
        else:
            lines = len(result.strip().split('\n'))
            expected_lines = (length + 15) // 16  # 16 bytes per line
            print(f"[OK] Got {lines} lines (expected ~{expected_lines})")
    
    return all_passed


def main():
    """Run all read_bytes tests."""
    print("\n" + "="*60)
    print("  READ_BYTES CAPABILITY TEST SUITE")
    print("  Testing NewMCP Plugin Integration")
    print("="*60)
    
    # Check connectivity first
    config = GhidraMCPConfig()
    client = GhidraMCPClient(config)
    
    if not client.health_check():
        print("\n[ERROR] Cannot connect to GhidraMCP server!")
        print("Make sure:")
        print("  1. Ghidra is running")
        print("  2. NewMCP plugin is installed and enabled")
        print("  3. A binary is loaded")
        print(f"  4. Server is running at {config.base_url}")
        return 1
    
    print(f"\n[OK] Connected to GhidraMCP at {config.base_url}")
    
    # Run tests
    results = []
    
    results.append(("Hex Format", test_read_bytes_hex_format()))
    results.append(("Raw/Base64 Format", test_read_bytes_raw_format()))
    results.append(("Multiple Addresses", test_read_bytes_multiple_addresses()))
    results.append(("Boundary Conditions", test_read_bytes_boundary_conditions()))
    
    # Summary
    print("\n" + "="*60)
    print("  TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status} {name}")
    
    print(f"\n  Total: {passed}/{total} tests passed")
    print("="*60)
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())

