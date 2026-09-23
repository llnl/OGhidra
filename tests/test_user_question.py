"""Tests for typed user questions emitted by the DSPy program."""

from src.user_question import UserQuestion


def test_question_display_with_options():
    question = UserQuestion(
        question="What next?",
        options=["Trace crypto", "Follow network"],
        allow_custom=True,
    )

    display = question.format_for_display()

    assert "❓ What next?" in display
    assert "1. Trace crypto" in display
    assert "2. Follow network" in display
    assert "3. [Type your own answer]" in display


def test_question_display_without_options():
    display = UserQuestion(question="What should I do?").format_for_display()

    assert "❓ What should I do?" in display
    assert "1." not in display
