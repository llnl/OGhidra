
import json
import os

# Get the path to the logs directory relative to this script
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
log_path = os.path.join(project_root, 'logs', 'llm_interactions.log')

try:
    with open(log_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    print(f"Total lines: {len(lines)}")
    
    # Find the last few 'generate' interactions
    generations = []
    for line in lines:
        try:
            data = json.loads(line)
            if data.get('interaction_type') == 'generate':
                generations.append(data)
        except:
            continue
            
    # Print the last 3 generations with prompt text (Reasoning)
    for i, gen in enumerate(generations[-5:]):
        print(f"\n--- GENERATION -{5-i} ---")
        print(f"Phase: {gen.get('phase')}")
        
        # Try to extract the 'REASONING' from the response if it exists
        response = gen.get('response', '')
        if "REASONING:" in response:
            reasoning = response.split("REASONING:")[1].split("EXECUTE:")[0].strip()
            print(f"REASONING: {reasoning}")
        else:
            print(f"Response (Fragment): {response[:200]}...")
            
        # Check if it was an empty or confusing response
        if not response or len(response) < 10:
             print("WARNING: EMPTY/SHORT RESPONSE")

except Exception as e:
    print(f"Error: {e}")
