"""Regression tests for Pydantic v2 validator behavior."""

import unittest
from datetime import datetime, timedelta

from pydantic import ValidationError

from src.config import BridgeConfig, GhidraMCPConfig, OllamaConfig, SessionHistoryConfig
from src.memory_models import SessionRecord
from src.models.memory import StructuredPrompt


class TestSessionRecordValidators(unittest.TestCase):
    def setUp(self):
        self.start_time = datetime(2025, 1, 1, 12, 0, 0)

    def test_end_time_after_start_time_is_accepted(self):
        end_time = self.start_time + timedelta(hours=1)

        record = SessionRecord(
            user_task_description="Analyze the sample",
            start_time=self.start_time,
            end_time=end_time,
        )

        self.assertEqual(record.end_time, end_time)

    def test_end_time_before_start_time_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "end_time cannot be before start_time"):
            SessionRecord(
                user_task_description="Analyze the sample",
                start_time=self.start_time,
                end_time=self.start_time - timedelta(seconds=1),
            )

    def test_end_time_more_than_one_day_after_start_time_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "Session duration cannot exceed 24 hours"):
            SessionRecord(
                user_task_description="Analyze the sample",
                start_time=self.start_time,
                end_time=self.start_time + timedelta(hours=24, seconds=1),
            )


class TestConfigurationValidators(unittest.TestCase):
    def test_ollama_validators_normalize_and_reject_invalid_values(self):
        config = OllamaConfig(review_thoroughness="THOROUGH", model="valid-model:1", model_map={"planning": "model"})

        self.assertEqual(config.review_thoroughness, "thorough")
        with self.assertRaises(ValidationError):
            OllamaConfig(model="invalid model")
        with self.assertRaises(ValidationError):
            OllamaConfig(model_map={"unsupported": "model"})

    def test_ghidra_validators_normalize_and_reject_invalid_values(self):
        config = GhidraMCPConfig(api_path="/api", backend=" PyGhidra ")

        self.assertEqual(config.backend, "pyghidra")
        with self.assertRaises(ValidationError):
            GhidraMCPConfig(api_path="api")
        with self.assertRaises(ValidationError):
            GhidraMCPConfig(backend="invalid")

    def test_session_history_validators_trim_and_reject_invalid_values(self):
        config = SessionHistoryConfig(storage_path="history.jsonl", vector_db_path=" vectors ")

        self.assertEqual(config.storage_path, "history.jsonl")
        self.assertEqual(config.vector_db_path, "vectors")
        with self.assertRaises(ValidationError):
            SessionHistoryConfig(storage_path="history.json")
        with self.assertRaises(ValidationError):
            SessionHistoryConfig(vector_db_path=" ")

    def test_bridge_validators_normalize_and_reject_invalid_values(self):
        config = BridgeConfig(log_level="warning", log_file=" bridge.log", knowledge_base_dir=" knowledge_base ")

        self.assertEqual(config.log_level, "WARNING")
        self.assertEqual(config.log_file, "bridge.log")
        self.assertEqual(config.knowledge_base_dir, "knowledge_base")
        with self.assertRaises(ValidationError):
            BridgeConfig(log_level="verbose")
        with self.assertRaises(ValidationError):
            BridgeConfig(log_file="bridge.txt")
        with self.assertRaises(ValidationError):
            BridgeConfig(knowledge_base_dir=" ")


class TestStructuredPromptValidator(unittest.TestCase):
    def test_conversation_history_is_preserved(self):
        conversation_history = []

        prompt = StructuredPrompt(conversation_history=conversation_history)

        self.assertEqual(prompt.conversation_history, conversation_history)
