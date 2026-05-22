"""
Unit tests for behavior summary extraction from function analysis text.
Tests the _extract_behavior_summary method in Bridge class.
"""

import sys
import os
import re

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _extract_behavior_summary(text: str) -> str:
    """
    Extract the first sentence after '**Behavior Summary:**' from function analysis.
    This is a copy of the Bridge method for testing purposes.
    """
    lines = text.split("\n")

    # Find "**Behavior Summary:**" section
    for i, line in enumerate(lines):
        if "**Behavior Summary:**" in line:
            # Get content from next non-empty line
            for j in range(i + 1, len(lines)):
                content = lines[j].strip()
                # Skip empty lines and section headers
                if content and not content.startswith("**"):
                    # Extract first sentence - improved regex to handle abbreviations
                    # Look for sentence terminators (. ! ?) followed by space and capital letter, or end of string
                    match = re.search(r"[.!?](?:\s+[A-Z]|\s*$)", content)
                    if match:
                        end_pos = match.start() + 1
                        return content[:end_pos].strip()
                    # No sentence terminator found - return up to 200 chars
                    return content[:200].strip()
            break

    # Fallback 1: Try plain "Behavior:" (backward compatibility)
    for i, line in enumerate(lines):
        if "Behavior:" in line and "**Behavior Summary:**" not in line:
            remaining = "\n".join(lines[i:]).replace("Behavior:", "").strip()
            match = re.search(r"[.!?](?:\s+[A-Z]|\s*$)", remaining)
            if match:
                end_pos = match.start() + 1
                return remaining[:end_pos].strip()
            return remaining[:200].strip()

    # Fallback 2: Return truncated full text
    return text[:200].strip() if text else "No summary available"


def test_standard_format():
    """Test extraction from standard function analysis format."""
    text = """**Function Analysis:**
The function `initializeExceptionWithMessage` initializes an exception object by setting its virtual function table.

**Behavior Summary:**
This function constructs and initializes a C++ exception object by setting its vftable, clearing its message field, and copying an exception message from a source structure into the object. It is likely part of the low-level exception handling infrastructure.

**Suggested Name:** constructStandardExceptionWithMessage
"""

    result = _extract_behavior_summary(text)
    expected = "This function constructs and initializes a C++ exception object by setting its vftable, clearing its message field, and copying an exception message from a source structure into the object."

    assert result == expected, f"Expected: {expected}\nGot: {result}"
    print("PASS test_standard_format")


def test_abbreviations():
    """Test that abbreviations with periods don't break sentence extraction."""
    text = """**Behavior Summary:**
Manages C++ objects in the C.R.T. runtime. The function validates input parameters.
"""

    result = _extract_behavior_summary(text)
    expected = "Manages C++ objects in the C.R.T. runtime."

    assert result == expected, f"Expected: {expected}\nGot: {result}"
    print("PASS test_abbreviations")


def test_backward_compatibility():
    """Test fallback to plain 'Behavior:' format."""
    text = """Function: validateInput
Address: 00401234
Behavior: Validates user input and returns status code. Additional processing occurs.
"""

    result = _extract_behavior_summary(text)
    expected = "Validates user input and returns status code."

    assert result == expected, f"Expected: {expected}\nGot: {result}"
    print("PASS test_backward_compatibility")


def test_network_malware():
    """Test extraction for network malware function."""
    text = """**Function Analysis:**
Detailed analysis of network communication...

**Behavior Summary:**
Establishes network socket connection to remote server and transmits system information including hostname, IP address, and running processes. Uses obfuscated API calls to evade detection.

**Suggested Name:** exfiltrateSystemData
"""

    result = _extract_behavior_summary(text)
    expected = "Establishes network socket connection to remote server and transmits system information including hostname, IP address, and running processes."

    assert result == expected, f"Expected: {expected}\nGot: {result}"
    print("PASS test_network_malware")


def test_short_summary():
    """Test handling of very short summaries."""
    text = """**Behavior Summary:**
No-op function.
"""

    result = _extract_behavior_summary(text)
    expected = "No-op function."

    assert result == expected, f"Expected: {expected}\nGot: {result}"
    print("PASS test_short_summary")


def test_no_behavior_summary():
    """Test fallback when no Behavior Summary section exists."""
    text = """Some random text without behavior summary section."""

    result = _extract_behavior_summary(text)

    # Should return truncated text
    assert len(result) <= 200, f"Expected truncated text, got: {result}"
    assert "Some random text" in result, f"Expected fallback text, got: {result}"
    print("PASS test_no_behavior_summary")


def test_multiline_summary():
    """Test that only first sentence is extracted from multi-line summary."""
    text = """**Behavior Summary:**
This function allocates memory for data structures. It then initializes the structures. Finally it returns a pointer.
"""

    result = _extract_behavior_summary(text)
    expected = "This function allocates memory for data structures."

    assert result == expected, f"Expected: {expected}\nGot: {result}"
    print("PASS test_multiline_summary")


def test_exclamation_mark():
    """Test sentence extraction with exclamation mark."""
    text = """**Behavior Summary:**
This function raises a critical security exception! The program terminates immediately.
"""

    result = _extract_behavior_summary(text)
    expected = "This function raises a critical security exception!"

    assert result == expected, f"Expected: {expected}\nGot: {result}"
    print("PASS test_exclamation_mark")


if __name__ == "__main__":
    print("Running behavior summary extraction tests...\n")

    try:
        test_standard_format()
        test_abbreviations()
        test_backward_compatibility()
        test_network_malware()
        test_short_summary()
        test_no_behavior_summary()
        test_multiline_summary()
        test_exclamation_mark()

        print("\nALL TESTS PASSED!")

    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
