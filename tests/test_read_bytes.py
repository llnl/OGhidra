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
    pytest -m integration tests/test_read_bytes.py
"""

import base64
import os
import sys

import pytest

# Add project root to path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.config import GhidraMCPConfig  # noqa: E402
from src.ghidra_client import GhidraMCPClient  # noqa: E402

# Every test in this module talks to a live GhidraMCP server, so none of them can
# run in CI. They are deselected by the `-m "not integration"` default in
# pyproject.toml and run explicitly with `pytest -m integration`.
pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def require_ghidra_mcp_server():
    """Skip rather than fail when there is no GhidraMCP server to talk to."""
    config = GhidraMCPConfig()
    if not GhidraMCPClient(config).health_check():
        pytest.skip(f"No GhidraMCP server reachable at {config.base_url}")


def test_read_bytes_hex_format():
    """Test reading bytes in hex dump format."""
    print("\n" + "=" * 60)
    print("TEST: read_bytes (hex format)")
    print("=" * 60)

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
    assert "Error" not in result and "No program" not in result, f"Error reading bytes: {result}"

    # Check for expected bytes (function prologue)
    # 55 = PUSH RBP, 57 = PUSH RDI, 56 = PUSH RSI, 53 = PUSH RBX
    expected_start = "55 57 56 53"
    if expected_start.upper() in result.upper():
        print(f"\n[PASS] Found expected prologue bytes: {expected_start}")
        return

    # A different binary is fine, but the response must still be a valid hex dump.
    print(f"\n[INFO] Did not find expected bytes '{expected_start}' - may be different binary")
    print("[INFO] Checking if we got valid hex dump format...")
    assert ":" in result and "|" in result, f"Response is not a valid hex dump: {result}"
    print("[PASS] Valid hex dump format received")


def test_read_bytes_raw_format():
    """Test reading bytes in base64 raw format."""
    print("\n" + "=" * 60)
    print("TEST: read_bytes (raw/base64 format)")
    print("=" * 60)

    config = GhidraMCPConfig()
    client = GhidraMCPClient(config)

    test_address = "10040fae0"

    print(f"\nReading 16 bytes from address 0x{test_address} in raw format...")
    result = client.read_bytes(test_address, length=16, format="raw")

    print("\nResult (base64):")
    print("-" * 50)
    print(result)
    print("-" * 50)

    assert "Error" not in result and "No program" not in result, f"Error reading bytes: {result}"

    try:
        decoded = base64.b64decode(result)
    except Exception as e:
        pytest.fail(f"Could not decode base64: {e}")

    print(f"\n[PASS] Successfully decoded {len(decoded)} bytes from base64")
    print(f"Raw bytes (hex): {decoded.hex()}")


def test_read_bytes_multiple_addresses():
    """Test reading from multiple addresses in the function."""
    print("\n" + "=" * 60)
    print("TEST: read_bytes from multiple function addresses")
    print("=" * 60)

    config = GhidraMCPConfig()
    client = GhidraMCPClient(config)

    # Test several addresses from the function disassembly
    test_cases = [
        ("10040fae0", "Function entry (PUSH RBP)"),
        ("10040fae8", "MOV RDI instruction"),
        ("10040faef", "MOV RSI instruction"),
        ("10040fb02", "JZ instruction"),
    ]

    failures = []
    for address, description in test_cases:
        print(f"\n--- {description} @ 0x{address} ---")
        result = client.read_bytes(address, length=8, format="hex")

        if "Error" in result or not result.strip():
            print(f"[FAIL] Could not read from 0x{address}")
            failures.append(f"0x{address} ({description}): {result.strip() or '(empty)'}")
        else:
            # Just show first line of hex dump
            first_line = result.split("\n")[0] if result else "(empty)"
            print(f"[OK] {first_line}")

    assert not failures, "Could not read from:\n  " + "\n  ".join(failures)


def test_read_bytes_boundary_conditions():
    """Test edge cases and boundary conditions."""
    print("\n" + "=" * 60)
    print("TEST: read_bytes boundary conditions")
    print("=" * 60)

    config = GhidraMCPConfig()
    client = GhidraMCPClient(config)

    test_cases = [
        ("10040fae0", 1, "Minimum length (1 byte)"),
        ("10040fae0", 256, "Medium length (256 bytes)"),
        ("10040fae0", 4096, "Maximum length (4096 bytes)"),
    ]

    failures = []
    for address, length, description in test_cases:
        print(f"\n--- {description} ---")
        result = client.read_bytes(address, length=length, format="hex")

        if "Error" in result:
            if "Length must be" in result and length > 4096:
                print("[PASS] Correctly rejected length > 4096")
            else:
                print(f"[FAIL] {result}")
                failures.append(f"{description}: {result.strip()}")
        else:
            lines = len(result.strip().split("\n"))
            expected_lines = (length + 15) // 16  # 16 bytes per line
            print(f"[OK] Got {lines} lines (expected ~{expected_lines})")

    assert not failures, "Boundary checks failed:\n  " + "\n  ".join(failures)


def main():
    """Run all read_bytes tests."""
    print("\n" + "=" * 60)
    print("  READ_BYTES CAPABILITY TEST SUITE")
    print("  Testing NewMCP Plugin Integration")
    print("=" * 60)

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
    checks = [
        ("Hex Format", test_read_bytes_hex_format),
        ("Raw/Base64 Format", test_read_bytes_raw_format),
        ("Multiple Addresses", test_read_bytes_multiple_addresses),
        ("Boundary Conditions", test_read_bytes_boundary_conditions),
    ]

    results = []
    for name, check in checks:
        try:
            check()
        except AssertionError as e:
            print(f"\n[FAIL] {e}")
            results.append((name, False))
        else:
            results.append((name, True))

    # Summary
    print("\n" + "=" * 60)
    print("  TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, r in results if r)
    total = len(results)

    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status} {name}")

    print(f"\n  Total: {passed}/{total} tests passed")
    print("=" * 60)

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
