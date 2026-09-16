import os
import sys
import unittest
from unittest.mock import MagicMock

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.bridge import Bridge  # noqa: E402
from src.context_manager import ContextManager, ResultCache  # noqa: E402


class TestResultCacheScopes(unittest.TestCase):
    def test_scoped_results_can_be_retrieved_per_program(self):
        cache = ResultCache(max_cache_size=10)
        cache.store(
            "decompile_function",
            {"name": "main"},
            "prog1 result",
            custom_id="step_L1_1",
            cache_scopes=["prog1", "/prog1"],
            scope_label="prog1",
        )
        cache.store(
            "decompile_function",
            {"name": "main"},
            "prog2 result",
            custom_id="step_L1_2",
            cache_scopes=["prog2", "/prog2"],
            scope_label="prog2",
        )

        self.assertEqual(cache.get_full_result("step_L1_1", cache_scope="prog1"), "prog1 result")
        self.assertEqual(cache.get_full_result("step_L1_2", cache_scope="/prog2"), "prog2 result")
        self.assertIsNone(cache.get_full_result("step_L1_1", cache_scope="prog2"))


class TestBridgeScopedCachedResults(unittest.TestCase):
    def setUp(self):
        self.bridge = Bridge.__new__(Bridge)
        self.bridge.logger = MagicMock()
        self.bridge.context_manager = ContextManager(enable_caching=True)
        self.bridge.ghidra_client = MagicMock()

    def test_generate_cache_key_includes_program_scope(self):
        key = self.bridge._generate_cache_key(
            "decompile_function",
            {"name": "main", "__cache_scope": "/prog1"},
        )
        self.assertEqual(key, "/prog1|decompile_function:main")

    def test_get_cached_result_honors_program_scope(self):
        self.bridge.context_manager.result_cache.store(
            "list_functions",
            {"limit": 10},
            "prog1 functions",
            custom_id="step_L1_3",
            cache_scopes=["prog1", "/prog1"],
            scope_label="prog1",
        )

        result = self.bridge.get_cached_result("step_L1_3", program="prog1")
        self.assertIn("[Cache Scope: prog1]", result)
        self.assertIn("prog1 functions", result)

        error = self.bridge.get_cached_result("step_L1_3", program="prog2")
        self.assertIn("not found for program 'prog2'", error)


if __name__ == "__main__":
    unittest.main()
