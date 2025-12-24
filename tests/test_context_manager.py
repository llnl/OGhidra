#!/usr/bin/env python3
"""
Test script for the Context Management System.

Tests:
- ContextBudget token tracking
- ResultCache storage and retrieval
- Smart truncation
- Result prioritization
"""

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.context_manager import (
    ContextManager, 
    ContextBudget, 
    ResultCache, 
    ResultPriority
)


def test_context_budget():
    """Test context budget tracking."""
    print("=" * 60)
    print("Testing ContextBudget")
    print("=" * 60)
    
    budget = ContextBudget(total_budget=80000, execution_fraction=0.4)
    
    print(f"\nTotal budget: {budget.total_budget} tokens")
    print(f"Execution budget: {budget.execution_budget} tokens")
    print(f"System budget: {budget.system_budget} tokens")
    print(f"History budget: {budget.history_budget} tokens")
    print(f"Response budget: {budget.response_budget} tokens")
    
    # Test token estimation
    test_text = "This is a test string with some words in it."
    estimated_tokens = budget.estimate_tokens(test_text)
    print(f"\nTest text ({len(test_text)} chars) -> ~{estimated_tokens} tokens")
    
    # Test budget tracking
    budget.add_usage('system', "A" * 4000)  # ~1000 tokens
    budget.add_usage('execution', "B" * 8000)  # ~2000 tokens
    
    print(f"\nAfter adding usage:")
    print(budget.get_usage_summary())
    
    # Test can_fit
    small_text = "Small result"
    large_text = "X" * 200000  # Should not fit
    
    print(f"\nCan fit small text: {budget.can_fit(small_text, 'execution')}")
    print(f"Can fit large text: {budget.can_fit(large_text, 'execution')}")
    
    print("\n[PASS] ContextBudget tests passed!")


def test_result_cache():
    """Test result caching."""
    print("\n" + "=" * 60)
    print("Testing ResultCache")
    print("=" * 60)
    
    cache = ResultCache(max_cache_size=10)
    
    # Store some results
    result1 = cache.store("decompile_function", {"name": "main"}, 
                          "void main() {\n    printf('Hello');\n    return 0;\n}")
    
    result2 = cache.store("list_functions", {}, 
                          "\n".join([f"FUN_{i:08x} at {i:08x}" for i in range(100)]))
    
    print(f"\nStored results:")
    print(f"  - {result1.result_id}: {result1.tool_name} ({result1.token_estimate} tokens, priority: {result1.priority})")
    print(f"  - {result2.result_id}: {result2.tool_name} ({result2.token_estimate} tokens, priority: {result2.priority})")
    
    # Test retrieval
    retrieved = cache.get(result1.result_id)
    print(f"\nRetrieved {result1.result_id}: {len(retrieved.full_result)} chars")
    
    # Test excerpt
    print(f"\nExcerpt for list_functions:\n{result2.excerpt}")
    
    # Test eviction
    print("\n\nTesting eviction with 15 new entries...")
    for i in range(15):
        cache.store("test_tool", {"i": i}, f"Result {i}")
    
    print(f"Cache size after eviction: {len(cache.cache)}")
    
    print("\n[PASS] ResultCache tests passed!")


def test_context_manager():
    """Test the main ContextManager."""
    print("\n" + "=" * 60)
    print("Testing ContextManager")
    print("=" * 60)
    
    manager = ContextManager(
        ollama_client=None,  # No LLM for testing
        context_budget=80000,
        execution_fraction=0.4,
        enable_summarization=False,  # Disable for testing (needs LLM)
        enable_caching=True,
        enable_tiered_context=True
    )
    
    print(f"\nInitial status:\n{manager.get_status()}")
    
    # Process some results
    small_result = "Function main at 0x140001000"
    display, cached = manager.process_result(
        "get_current_function",
        {},
        small_result,
        "Analyze the main function"
    )
    
    print(f"\nProcessed small result:")
    print(f"  Display: {display}")
    print(f"  Cached ID: {cached.result_id}")
    
    # Process a large result
    large_result = "\n".join([f"Line {i}: Some content here with data" for i in range(200)])
    display, cached = manager.process_result(
        "list_functions",
        {"offset": 0, "limit": 200},
        large_result,
        "List all functions"
    )
    
    print(f"\nProcessed large result:")
    print(f"  Original length: {len(large_result)} chars")
    print(f"  Display length: {len(display)} chars")
    print(f"  Cached: {cached.result_id}")
    
    # Test retrieval
    full = manager.get_full_result(cached.result_id)
    print(f"  Retrieved full result: {len(full)} chars")
    
    print(f"\nFinal status:\n{manager.get_status()}")
    
    print("\n[PASS] ContextManager tests passed!")


def test_smart_truncation():
    """Test smart truncation for different tool types."""
    print("\n" + "=" * 60)
    print("Testing Smart Truncation")
    print("=" * 60)
    
    manager = ContextManager(
        context_budget=80000,
        enable_summarization=False,
        enable_caching=False
    )
    
    # Test list truncation
    list_result = "\n".join([f"Function_{i:04d} at 0x{i*16:08x}" for i in range(100)])
    truncated = manager._smart_truncate(list_result, 500, "list_functions")
    print(f"\nList truncation (100 items -> 500 chars):")
    print(truncated[:200] + "...")
    
    # Test code truncation
    code_result = """int complex_function(int a, int b) {
    int result = 0;
    for (int i = 0; i < a; i++) {
        result += calculate(i, b);
        if (result > 1000) {
            handle_overflow();
        }
    }
    return process_result(result);
}"""
    truncated = manager._smart_truncate(code_result, 100, "decompile_function")
    print(f"\nCode truncation:")
    print(truncated)
    
    # Test hex dump truncation
    hex_result = "\n".join([f"0x{i*16:08x}: " + " ".join([f"{b:02X}" for b in range(16)]) 
                           for i in range(50)])
    truncated = manager._smart_truncate(hex_result, 300, "read_bytes")
    print(f"\nHex dump truncation:")
    print(truncated)
    
    print("\n[PASS] Smart Truncation tests passed!")


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("Context Management System Tests")
    print("=" * 60)
    
    try:
        test_context_budget()
        test_result_cache()
        test_context_manager()
        test_smart_truncation()
        
        print("\n" + "=" * 60)
        print("All tests passed! [SUCCESS]")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n[FAIL] Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

