import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from oghidra_workflows.config import (
    AppConfig,
    HttpServerConfig,
    StdioServerConfig,
    load_config,
)


def valid_config():
    return {
        "lm": {"model": "openai/test"},
        "mcp_servers": {"ghidra": {"transport": "stdio", "command": "python"}},
    }


def test_load_yaml_produces_nested_models(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("""lm:
  model: openai/test
mcp_servers:
  ghidra:
    transport: stdio
    command: python
compiled_predictor: predictor.json
""")
    config = load_config(path)
    assert config.lm.model == "openai/test"
    assert config.max_iters == 6
    assert isinstance(config.mcp_servers["ghidra"], StdioServerConfig)
    assert config.compiled_predictor == str(tmp_path / "predictor.json")


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_iters", "6"),
        ("max_iters", True),
        ("max_iters", 0),
        ("max_iter", 6),
        ("compiled_predictor", 123),
    ],
)
def test_root_fields_reject_invalid_values(field, value):
    data = valid_config()
    data[field] = value
    with pytest.raises(ValidationError):
        AppConfig.model_validate(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("cache", "false"),
        ("max_tokens", "4096"),
        ("max_tokens", -1),
        ("temprature", 0.5),
        ("temperature", "0.5"),
        ("temperature", float("inf")),
        ("timeout", 0),
        ("api_base", "file:///tmp/model"),
        ("api_key_env", 123),
    ],
)
def test_lm_fields_reject_invalid_values(field, value):
    data = valid_config()
    data["lm"][field] = value
    with pytest.raises(ValidationError):
        AppConfig.model_validate(data)


@pytest.mark.parametrize(
    "server",
    [
        {"transport": "stdio", "url": "http://localhost/mcp"},
        {"transport": "stdio", "command": "python", "url": "http://localhost/mcp"},
        {"transport": "sse", "command": "python"},
        {"transport": "streamable-http", "url": "http://localhost/mcp", "args": []},
        {"transport": "unknown", "command": "python"},
        {"command": "python"},
        {"transport": "stdio", "command": "python", "args": [123]},
        {"transport": "stdio", "command": "python", "env": {"PORT": 8080}},
    ],
)
def test_transport_contracts(server):
    data = valid_config()
    data["mcp_servers"]["ghidra"] = server
    with pytest.raises(ValidationError):
        AppConfig.model_validate(data)


@pytest.mark.parametrize("transport", ["sse", "streamable-http"])
def test_http_union(transport):
    data = valid_config()
    data["mcp_servers"]["ghidra"] = {
        "transport": transport,
        "url": "http://localhost:8081/mcp",
    }
    config = AppConfig.model_validate(data)
    assert isinstance(config.mcp_servers["ghidra"], HttpServerConfig)


def test_ghidra_required():
    data = valid_config()
    data["mcp_servers"] = {}
    with pytest.raises(ValidationError, match="ghidra"):
        AppConfig.model_validate(data)


def test_no_later_field_reassignment():
    config = AppConfig.model_validate(valid_config())
    with pytest.raises(ValidationError, match="frozen"):
        config.max_iters = "bad"


def test_examples_and_generated_schema_are_current():
    root = Path(__file__).resolve().parents[1]
    assert isinstance(load_config(root / "config.example.yaml"), AppConfig)
    assert (
        json.loads((root / "config.schema.json").read_text())
        == AppConfig.model_json_schema()
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("log_level", "TRACE"),
        ("log_max_bytes", 0),
        ("log_max_bytes", "5000"),
        ("log_backup_count", 0),
        ("log_file", 123),
    ],
)
def test_logging_settings_are_strict(field, value):
    data = valid_config()
    data[field] = value
    with pytest.raises(ValidationError):
        AppConfig.model_validate(data)
