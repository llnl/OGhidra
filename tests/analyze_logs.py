import json
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
log_path = os.path.join(project_root, "logs", "llm_interactions.log")

with open(log_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Get last 20 generate interactions
generates = []
for line in lines:
    try:
        data = json.loads(line.strip())
        if data.get("interaction_type") == "generate":
            generates.append(data)
    except:
        pass

# Print last 10 generate calls with key stats
for g in generates[-10:]:
    tokens = g.get("tokens", {})
    print("---")
    print(f"Phase: {g.get('phase', 'N/A')}")
    print(f"Method: {g.get('method', 'N/A')}")
    print(f"Prompt tokens: {tokens.get('prompt_token_count', 'N/A')}")
    print(f"Response tokens: {tokens.get('candidates_token_count', 'N/A')}")
    print(f"Finish reason: {g.get('finish_reason', 'NOT LOGGED')}")
    print(f"Response length: {len(g.get('response', ''))}")
    resp_preview = g.get("response", "")[:200]
    print(f"Response preview: {resp_preview[:100]}...")
