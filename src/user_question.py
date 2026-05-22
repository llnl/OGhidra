"""
User Question Tool — AI-initiated questions during investigation.

Inspired by OpenCode's Question.ask()/reply() system. Allows the AI
to pause execution and ask the user structured questions with predefined
options or freeform input.

Directive format in LLM response:
    ASK_USER: What area should I focus on next?
    OPTIONS: Crypto imports | Network callbacks | String obfuscation

The execution loop parses this, emits the question to the UI,
and pauses until the user answers.
"""

import re
import logging
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


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
    options: List[str] = Field(default_factory=list)
    allow_custom: bool = True
    context: Dict[str, Any] = Field(default_factory=dict)

    def format_for_display(self) -> str:
        """Format question for terminal/log display."""
        lines = [f"❓ {self.question}"]
        if self.options:
            for i, opt in enumerate(self.options, 1):
                lines.append(f"   {i}. {opt}")
            if self.allow_custom:
                lines.append(f"   {len(self.options) + 1}. [Type your own answer]")
        return "\n".join(lines)


# Regex patterns for parsing ASK_USER directive from LLM output
_ASK_USER_PATTERN = re.compile(r"ASK_USER:\s*(.+?)(?:\n|$)", re.IGNORECASE)
_OPTIONS_PATTERN = re.compile(r"OPTIONS:\s*(.+?)(?:\n|$)", re.IGNORECASE)


class QuestionHandler:
    """Manages the ask → answer flow between AI and user.

    Lifecycle:
    1. parse_from_response() — detects ASK_USER in LLM output
    2. UI collects answer (via _ui_question_callback or terminal input())
    3. set_answer() — stores the user's response
    4. consume_answer() — returns and clears the answer for prompt injection
    """

    def __init__(self):
        self._pending: Optional[UserQuestion] = None
        self._answer: Optional[str] = None

    def parse_from_response(self, response: str) -> Optional[UserQuestion]:
        """Parse ASK_USER: directive from an LLM response.

        Expected format:
            ASK_USER: What should I investigate next?
            OPTIONS: Option A | Option B | Option C

        OPTIONS line is optional. If absent, freeform-only.

        Returns:
            UserQuestion if directive found, None otherwise.
        """
        match = _ASK_USER_PATTERN.search(response)
        if not match:
            return None

        question_text = match.group(1).strip()

        # Parse optional OPTIONS line
        options = []
        opt_match = _OPTIONS_PATTERN.search(response)
        if opt_match:
            raw_options = opt_match.group(1).strip()
            options = [o.strip() for o in raw_options.split("|") if o.strip()]

        # Generate a short header from the question
        header = question_text[:30].rstrip()
        if len(question_text) > 30:
            header = header.rsplit(" ", 1)[0] + "…"

        question = UserQuestion(
            question=question_text,
            header=header,
            options=options,
            allow_custom=True,
        )

        self._pending = question
        logger.info(f"Parsed user question: {question_text} ({len(options)} options)")
        return question

    @property
    def pending_question(self) -> Optional[UserQuestion]:
        """Currently pending question (waiting for answer)."""
        return self._pending

    def set_answer(self, answer: str):
        """Store the user's answer. Called by UI or terminal fallback."""
        self._answer = answer
        logger.info(f"User answered: {answer[:100]}")

    def consume_answer(self) -> Optional[str]:
        """Return and clear the pending answer.

        Returns None if no answer has been provided yet.
        """
        answer = self._answer
        self._answer = None
        self._pending = None
        return answer

    def format_answer_for_prompt(self, question: UserQuestion, answer: str) -> str:
        """Format the user's answer for injection into the next execution prompt.

        Returns a section that gets appended to the execution prompt:
            ## User Response
            Question: What area should I focus on?
            Answer: Crypto imports

            Incorporate this feedback into your next steps.
        """
        return (
            f"\n## User Response\n"
            f"Question: {question.question}\n"
            f"Answer: {answer}\n\n"
            f"Incorporate this feedback into your next steps.\n"
        )

    def reset(self):
        """Clear all state."""
        self._pending = None
        self._answer = None
        logger.debug("QuestionHandler reset")
