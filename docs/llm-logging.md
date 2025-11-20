# LLM Interaction Logging

OGhidra now includes comprehensive logging of all LLM (Large Language Model) interactions with Ollama. This feature helps you monitor, debug, and analyze AI interactions.

## Configuration

All LLM logging settings are configured via the `.env` file:

```bash
# Enable LLM logging
LLM_LOGGING_ENABLED=true

# Log file location
LLM_LOG_FILE=logs/llm_interactions.log

# What to log
LLM_LOG_PROMPTS=true      # Log prompts sent to LLM
LLM_LOG_RESPONSES=true    # Log responses from LLM
LLM_LOG_TOKENS=true       # Log token counts
LLM_LOG_TIMING=true       # Log timing information

# Log format: 'json' or 'text'
LLM_LOG_FORMAT=json
```

## Log Formats

### JSON Format (Recommended)
Structured JSON logs that are easy to parse and analyze programmatically:

```json
{
  "timestamp": "2025-11-17T11:30:24.515509",
  "interaction_type": "generate",
  "model": "gemma3:4b",
  "method": "generate",
  "prompt": "Your prompt here...",
  "system_prompt": "System instructions...",
  "temperature": 0.7,
  "response": "AI response here...",
  "response_length": 150,
  "tokens": {
    "prompt_eval_count": 56,
    "eval_count": 150,
    "total_count": 206
  },
  "timing": {
    "total_duration_seconds": 2.79,
    "total_duration_ms": 741.35,
    "load_duration_ms": 263.80,
    "prompt_eval_duration_ms": 341.71,
    "eval_duration_ms": 134.62
  },
  "status": "success"
}
```

### Text Format
Human-readable format for quick review:

```
================================================================================
Timestamp: 2025-11-17T11:30:24.515509
Type: generate
model: gemma3:4b
prompt: Your prompt here...
response: AI response here...
timing: {...}
================================================================================
```

## Features

### Captured Information
- **Prompts**: Full text of prompts sent to the LLM
- **System Prompts**: System instructions used
- **Responses**: Complete AI-generated responses
- **Token Counts**: Prompt tokens, response tokens, and totals
- **Timing**: Request duration, model load time, evaluation times
- **Model**: Which model was used for the interaction
- **Status**: Success or error status

### Use Cases
1. **Debugging**: Track exact prompts and responses for troubleshooting
2. **Performance Analysis**: Monitor token usage and response times
3. **Cost Tracking**: Calculate API costs based on token counts (if using paid APIs)
4. **Quality Assurance**: Review AI responses for consistency
5. **Training Data**: Collect interaction data for analysis

## Privacy Considerations

⚠️ **Important**: The log files contain all prompts and responses, which may include:
- Sensitive code analysis results
- Binary file contents
- Function names and logic

**Recommendations**:
- Store log files securely
- Add `logs/` to `.gitignore` (already configured)
- Rotate/delete logs regularly
- Review before sharing logs

## Disabling Specific Components

You can selectively disable logging components:

```bash
LLM_LOGGING_ENABLED=true
LLM_LOG_PROMPTS=true
LLM_LOG_RESPONSES=false    # Don't log responses
LLM_LOG_TOKENS=true
LLM_LOG_TIMING=true
```

## Log File Management

### Location
Default: `logs/llm_interactions.log`

The directory is created automatically if it doesn't exist.

### Rotation
Logs append to the file. Consider implementing log rotation:
- Manually: Rename/archive old logs periodically
- Automated: Use tools like `logrotate` (Linux) or PowerShell scripts (Windows)

### Analysis Tools
JSON logs can be analyzed with standard tools:
- `jq`: Command-line JSON processor
- Python: `json` module
- Text editors with JSON support

## Example Analysis

### Count total interactions
```bash
# Linux/Mac
grep -c '"interaction_type"' logs/llm_interactions.log

# Windows PowerShell
(Get-Content logs/llm_interactions.log | Select-String '"interaction_type"').Count
```

### Calculate total tokens used
```python
import json

total_tokens = 0
with open('logs/llm_interactions.log') as f:
    for line in f:
        try:
            entry = json.loads(line)
            if 'tokens' in entry:
                total_tokens += entry['tokens']['total_count']
        except json.JSONDecodeError:
            pass

print(f"Total tokens: {total_tokens}")
```

### Find slow interactions
```python
import json

slow_interactions = []
with open('logs/llm_interactions.log') as f:
    for line in f:
        try:
            entry = json.loads(line)
            if 'timing' in entry:
                if entry['timing']['total_duration_seconds'] > 5:
                    slow_interactions.append({
                        'timestamp': entry['timestamp'],
                        'duration': entry['timing']['total_duration_seconds'],
                        'model': entry['model']
                    })
        except json.JSONDecodeError:
            pass

for interaction in slow_interactions:
    print(f"{interaction['timestamp']}: {interaction['duration']:.2f}s with {interaction['model']}")
```

## Troubleshooting

### Logs not being created
1. Check that `LLM_LOGGING_ENABLED=true` in `.env`
2. Verify the log directory is writable
3. Check application logs for errors

### Large log files
- Implement log rotation
- Reduce logging scope (disable prompts/responses)
- Archive old logs regularly

### Performance impact
LLM logging has minimal performance impact:
- File I/O is asynchronous
- Only enabled interactions are logged
- JSON serialization is efficient

