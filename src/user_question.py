"""Typed user questions emitted by the DSPy execution program."""

from typing import Any

from pydantic import BaseModel, Field


class UserQuestion(BaseModel):
    """A structured question the AI wants to ask the user.

    Mirrors OpenCode's Question.Info schema:
    - question: The full question text
    - header: Short label for UI display
    - options: Predefined answer choices
    - allow_custom: Whether the user can type a freeform answer
    """

    question: str
    header: str = ""
    options: list[str] = Field(default_factory=list)
    allow_custom: bool = True
    context: dict[str, Any] = Field(default_factory=dict)

    def format_for_display(self) -> str:
        """Format question for terminal/log display."""
        lines = [f"❓ {self.question}"]
        if self.options:
            for i, opt in enumerate(self.options, 1):
                lines.append(f"   {i}. {opt}")
            if self.allow_custom:
                lines.append(f"   {len(self.options) + 1}. [Type your own answer]")
        return "\n".join(lines)
