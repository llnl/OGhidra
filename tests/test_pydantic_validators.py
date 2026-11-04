"""Regression tests for Pydantic v2 validator behavior."""

import json
import unittest
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError

from src.config import (
    BridgeConfig,
    CustomAPIConfig,
    ExternalConfig,
    GhidraMCPConfig,
    GoogleConfig,
    OllamaConfig,
    SessionHistoryConfig,
)
from src.memory_models import SessionRecord
from src.models.memory import AnalysisState, PromptSection, SessionMemory, StructuredPrompt


class TestSessionRecordValidators(unittest.TestCase):
    def setUp(self):
        self.start_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)

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
    def test_environment_metadata_is_preserved_in_json_schemas(self):
        expected_metadata = (
            (OllamaConfig, "base_url", "OLLAMA_BASE_URL"),
            (GoogleConfig, "api_key", "GOOGLE_API_KEY"),
            (ExternalConfig, "provider", "EXTERNAL_PROVIDER"),
            (CustomAPIConfig, "api_url", "CUSTOM_API_URL"),
            (GhidraMCPConfig, "base_url", "GHIDRA_BASE_URL"),
            (BridgeConfig, "llm_provider", "LLM_PROVIDER"),
        )

        for model, field_name, environment_variable in expected_metadata:
            with self.subTest(model=model.__name__, field=field_name):
                field_schema = model.model_json_schema()["properties"][field_name]
                self.assertEqual(field_schema["env"], environment_variable)

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


class TestMemoryModelConfiguration(unittest.TestCase):
    def test_prompt_section_remains_frozen(self):
        section = PromptSection(name="goal", content="Analyze the sample", order=1)

        with self.assertRaises(ValidationError):
            section.name = "changed"

    def test_session_memory_serializes_datetimes_and_sets(self):
        start_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        memory = SessionMemory(
            start_time=start_time,
            analysis_state=AnalysisState(functions_decompiled={"alpha", "beta"}),
        )

        payload = json.loads(memory.model_dump_json())

        serialized_start_time = datetime.fromisoformat(payload["start_time"])
        self.assertEqual(serialized_start_time, start_time)
        self.assertEqual(set(payload["analysis_state"]["functions_decompiled"]), {"alpha", "beta"})
