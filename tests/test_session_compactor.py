"""
Tests for SessionCompactor — Smart context pruning.

Verifies:
    1. should_compact() returns True at threshold
    2. should_compact() returns False below threshold
    3. prune() keeps recent results, replaces old with cache refs
    4. prune() doesn't modify results under protect count
    5. compact() returns summary (mocked LLM)
    6. Disabled compactor always returns False
"""

import unittest
from unittest.mock import MagicMock
from src.session_compactor import SessionCompactor


class MockConfig:
    """Minimal config mock for compactor tests."""

    def __init__(self, **overrides):
        defaults = {
            "compaction_enabled": True,
            "compaction_threshold": 0.75,
            "compaction_auto": True,
            "context_budget": 10000,  # Small budget for testing
        }
        defaults.update(overrides)
        for k, v in defaults.items():
            setattr(self, k, v)


class MockToolExecution:
    """Minimal ToolExecution mock."""

    def __init__(self, tool_name="test_tool", parameters=None, result=""):
        self.tool_name = tool_name
        self.parameters = parameters or {}
        self.result = result


class MockExecResults:
    """Minimal ExecutionPhaseResults mock."""

    def __init__(self, tool_executions=None, goal="test goal", plan="test plan"):
        self.tool_executions = tool_executions or []
        self.goal = goal
        self.plan = plan
        self.compaction_summary = None


class TestShouldCompact(unittest.TestCase):
    """Test compaction threshold detection."""

    def test_over_threshold_triggers(self):
        """Context > 75% of budget should trigger compaction."""
        compactor = SessionCompactor(MockConfig(context_budget=1000))

        # Create results that total > 750 chars (75% of 1000)
        execs = [MockToolExecution(result="x" * 400) for _ in range(3)]  # 1200 chars
        results = MockExecResults(tool_executions=execs)

        self.assertTrue(compactor.should_compact(results))

    def test_under_threshold_no_trigger(self):
        """Context < 75% of budget should NOT trigger."""
        compactor = SessionCompactor(MockConfig(context_budget=10000))

        # Create results that total < 7500 chars
        execs = [MockToolExecution(result="x" * 100) for _ in range(3)]  # 300 chars
        results = MockExecResults(tool_executions=execs)

        self.assertFalse(compactor.should_compact(results))

    def test_disabled_never_triggers(self):
        """With compaction_enabled=False, should never trigger."""
        compactor = SessionCompactor(MockConfig(compaction_enabled=False))

        execs = [MockToolExecution(result="x" * 10000)]  # Way over any budget
        results = MockExecResults(tool_executions=execs)

        self.assertFalse(compactor.should_compact(results))

    def test_empty_results(self):
        """Empty results should not trigger compaction."""
        compactor = SessionCompactor(MockConfig(context_budget=100))
        results = MockExecResults(tool_executions=[])

        self.assertFalse(compactor.should_compact(results))


class TestPrune(unittest.TestCase):
    """Test deterministic pruning of old tool outputs."""

    def test_prunes_old_keeps_recent(self):
        """Old results should be replaced, recent ones kept intact."""
        compactor = SessionCompactor(MockConfig())
        compactor.protect_count = 3  # Protect last 3

        execs = [MockToolExecution(tool_name=f"tool_{i}", result="A" * 500) for i in range(6)]
        results = MockExecResults(tool_executions=execs)

        prune_result = compactor.prune(results)

        # First 3 should be pruned (contain [PRUNED])
        for i in range(3):
            self.assertIn("[PRUNED", str(execs[i].result))

        # Last 3 should be intact
        for i in range(3, 6):
            self.assertEqual(execs[i].result, "A" * 500)

        self.assertEqual(prune_result.results_pruned, 3)
        self.assertGreater(prune_result.original_chars, prune_result.compacted_chars)

    def test_nothing_to_prune_under_protect(self):
        """Fewer results than protect_count should not prune anything."""
        compactor = SessionCompactor(MockConfig())
        compactor.protect_count = 10

        execs = [MockToolExecution(result="A" * 500) for _ in range(5)]
        results = MockExecResults(tool_executions=execs)

        prune_result = compactor.prune(results)

        self.assertEqual(prune_result.results_pruned, 0)
        # All results should be intact
        for ex in execs:
            self.assertEqual(ex.result, "A" * 500)

    def test_short_results_not_pruned(self):
        """Results under 200 chars should not be pruned even if old."""
        compactor = SessionCompactor(MockConfig())
        compactor.protect_count = 2

        execs = [
            MockToolExecution(result="short"),  # < 200 chars, skip
            MockToolExecution(result="A" * 500),  # > 200 chars, prune
            MockToolExecution(result="B" * 500),  # protected
            MockToolExecution(result="C" * 500),  # protected
        ]
        results = MockExecResults(tool_executions=execs)

        compactor.prune(results)

        # First result too short to prune
        self.assertEqual(execs[0].result, "short")
        # Second should be pruned
        self.assertIn("[PRUNED", str(execs[1].result))


class TestCompact(unittest.TestCase):
    """Test LLM-driven compaction."""

    def test_compact_without_llm_falls_back(self):
        """Without LLM client, compact() should fall back to prune()."""
        compactor = SessionCompactor(MockConfig(), llm_client=None)
        compactor.protect_count = 2

        execs = [MockToolExecution(result="A" * 500) for _ in range(5)]
        results = MockExecResults(tool_executions=execs)

        compact_result = compactor.compact(results, "test goal")

        # Should fall back to prune strategy
        self.assertEqual(compact_result.strategy, "prune")

    def test_compact_with_mock_llm(self):
        """With a mock LLM, compact() should return an LLM summary."""
        mock_llm = MagicMock()
        mock_llm.chat.return_value = {"message": {"content": "Summarized: Found privilege escalation in WiseBootAssistant."}}

        compactor = SessionCompactor(MockConfig(), llm_client=mock_llm)

        execs = [MockToolExecution(result="x" * 500) for _ in range(3)]
        results = MockExecResults(tool_executions=execs)

        compact_result = compactor.compact(results, "test goal")

        self.assertEqual(compact_result.strategy, "compact")
        self.assertIsNotNone(compact_result.summary)
        self.assertIn("privilege escalation", compact_result.summary)
        mock_llm.chat.assert_called_once()

    def test_compact_llm_failure_falls_back(self):
        """If LLM chat() raises, _call_llm_for_summary falls back to _fallback_summary."""
        mock_llm = MagicMock()
        mock_llm.chat.side_effect = Exception("API error")

        compactor = SessionCompactor(MockConfig(), llm_client=mock_llm)
        compactor.protect_count = 2

        execs = [MockToolExecution(result="A" * 500) for _ in range(5)]
        results = MockExecResults(tool_executions=execs)

        compact_result = compactor.compact(results, "test goal")

        # _call_llm_for_summary catches the error and uses _fallback_summary,
        # so strategy is still 'compact' (not 'prune')
        self.assertEqual(compact_result.strategy, "compact")
        self.assertIsNotNone(compact_result.summary)


class TestEstimateUsage(unittest.TestCase):
    """Test context usage estimation."""

    def test_estimation_counts_chars(self):
        """estimate_context_usage should sum all result chars."""
        compactor = SessionCompactor(MockConfig(context_budget=10000))

        execs = [
            MockToolExecution(result="A" * 1000),
            MockToolExecution(result="B" * 2000),
        ]
        results = MockExecResults(tool_executions=execs, goal="goal", plan="plan")

        total, fraction = compactor.estimate_context_usage(results)

        # Should include results + tool names + parameters + goal + plan
        self.assertGreaterEqual(total, 3000)
        self.assertGreater(fraction, 0)


class TestReset(unittest.TestCase):
    """Test reset (no-op for now, but ensures interface exists)."""

    def test_reset_no_error(self):
        compactor = SessionCompactor(MockConfig())
        compactor.reset()  # Should not raise


if __name__ == "__main__":
    unittest.main()
