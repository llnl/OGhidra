"""
Tests for QuestionHandler — AI-initiated questions during investigation.

Verifies:
    1. Parse ASK_USER: with options from LLM response
    2. Parse ASK_USER: without options (freeform only)
    3. No false positives on normal tool responses
    4. Answer formatting into prompt
    5. Pending question cleared after consumption
    6. Reset clears all state
"""

import unittest
from src.user_question import UserQuestion, QuestionHandler


class TestParseFromResponse(unittest.TestCase):
    """Test parsing ASK_USER directive from LLM responses."""

    def setUp(self):
        self.handler = QuestionHandler()

    def test_parse_with_options(self):
        """Full ASK_USER with OPTIONS should parse correctly."""
        response = (
            "REASONING: I found three interesting areas to explore.\n"
            "ASK_USER: Which area should I focus on next?\n"
            "OPTIONS: Crypto imports | Network callbacks | String obfuscation"
        )
        q = self.handler.parse_from_response(response)
        self.assertIsNotNone(q)
        self.assertEqual(q.question, "Which area should I focus on next?")
        self.assertEqual(len(q.options), 3)
        self.assertIn("Crypto imports", q.options)
        self.assertIn("Network callbacks", q.options)
        self.assertIn("String obfuscation", q.options)
        self.assertTrue(q.allow_custom)

    def test_parse_without_options(self):
        """ASK_USER without OPTIONS should be freeform-only."""
        response = (
            "REASONING: I'm not sure which binary to analyze.\n"
            "ASK_USER: Which binary should I prioritize?"
        )
        q = self.handler.parse_from_response(response)
        self.assertIsNotNone(q)
        self.assertEqual(q.question, "Which binary should I prioritize?")
        self.assertEqual(q.options, [])
        self.assertTrue(q.allow_custom)

    def test_no_ask_user_returns_none(self):
        """Normal tool response without ASK_USER should return None."""
        response = (
            "REASONING: I will decompile the main function.\n"
            "EXECUTE: decompile_function(address=\"0x401000\")"
        )
        q = self.handler.parse_from_response(response)
        self.assertIsNone(q)

    def test_investigation_complete_returns_none(self):
        """INVESTIGATION COMPLETE should not trigger question parsing."""
        response = "INVESTIGATION COMPLETE"
        q = self.handler.parse_from_response(response)
        self.assertIsNone(q)

    def test_case_insensitive(self):
        """ASK_USER should be case-insensitive."""
        response = "ask_user: What should I do?"
        q = self.handler.parse_from_response(response)
        self.assertIsNotNone(q)
        self.assertEqual(q.question, "What should I do?")

    def test_header_generation(self):
        """Header should be a short version of the question (max 30 chars)."""
        response = "ASK_USER: Which of these three suspicious functions should I trace for privilege escalation?"
        q = self.handler.parse_from_response(response)
        self.assertIsNotNone(q)
        self.assertLessEqual(len(q.header), 35)  # 30 + ellipsis

    def test_sets_pending(self):
        """Parsing should set the pending question."""
        response = "ASK_USER: What next?"
        self.handler.parse_from_response(response)
        self.assertIsNotNone(self.handler.pending_question)
        self.assertEqual(self.handler.pending_question.question, "What next?")


class TestAnswerFlow(unittest.TestCase):
    """Test answer injection and consumption."""

    def setUp(self):
        self.handler = QuestionHandler()

    def test_set_and_consume_answer(self):
        """Answer should be stored and cleared on consumption."""
        self.handler.set_answer("Focus on crypto imports")
        answer = self.handler.consume_answer()
        self.assertEqual(answer, "Focus on crypto imports")
        # Second consumption should return None
        self.assertIsNone(self.handler.consume_answer())

    def test_no_answer_returns_none(self):
        """consume_answer without set should return None."""
        self.assertIsNone(self.handler.consume_answer())

    def test_format_answer_for_prompt(self):
        """Formatted answer should include question and answer text."""
        q = UserQuestion(question="Which area?", options=["A", "B"])
        formatted = self.handler.format_answer_for_prompt(q, "Option A")
        self.assertIn("Which area?", formatted)
        self.assertIn("Option A", formatted)
        self.assertIn("## User Response", formatted)
        self.assertIn("Incorporate this feedback", formatted)


class TestQuestionDisplay(unittest.TestCase):
    """Test UserQuestion display formatting."""

    def test_format_with_options(self):
        """Display should show numbered options."""
        q = UserQuestion(
            question="What next?",
            options=["Trace crypto", "Follow network"],
            allow_custom=True
        )
        display = q.format_for_display()
        self.assertIn("❓ What next?", display)
        self.assertIn("1. Trace crypto", display)
        self.assertIn("2. Follow network", display)
        self.assertIn("3. [Type your own answer]", display)

    def test_format_freeform_only(self):
        """Without options, display should just show the question."""
        q = UserQuestion(question="What should I do?")
        display = q.format_for_display()
        self.assertIn("❓ What should I do?", display)
        self.assertNotIn("1.", display)


class TestReset(unittest.TestCase):
    """Test reset clears all state."""

    def test_full_reset(self):
        handler = QuestionHandler()
        handler.parse_from_response("ASK_USER: Test?")
        handler.set_answer("answer")
        
        handler.reset()
        
        self.assertIsNone(handler.pending_question)
        self.assertIsNone(handler.consume_answer())


if __name__ == '__main__':
    unittest.main()
