# Helper method for execution-phase ranking
def _execution_agent_rank(self, tool_name: str, result: Any, goal: str, max_items: int = 20) -> Any:
    """
    Ask the execution agent to rank and filter large results.
    
    Args:
        tool_name: Name of the tool that produced the result
        result: The full result to rank  
        goal: Current user goal for relevance context
        max_items: Maximum items to keep (default: 20)
        
    Returns:
        Filtered result with top N most relevant items
    """
    # Parse result to count items
    result_str = json.dumps(result, indent=2) if isinstance(result, (dict, list)) else str(result)
    
    # Try to count items based on tool type
    item_count = 0
    if isinstance(result, list):
        item_count = len(result)
    elif isinstance(result, dict):
        if 'items' in result:
            item_count = len(result.get('items', []))
        elif 'functions' in result:
            item_count = len(result.get('functions', []))
        elif 'imports' in result:
            item_count = len(result.get('imports', []))
    
    # Truncate preview to show representative sample
    preview_lines = result_str.split('\n')[:50]
    preview = '\n'.join(preview_lines)
    if len(preview_lines) >= 50:
        preview += f"\n... ({len(result_str.split(chr(10))) - 50} more lines)"
    
    ranking_prompt = f"""You just executed `{tool_name}` and received {item_count} results.

GOAL: {goal}

Results Preview (first 50 lines):
{preview}

TASK: Select the {max_items} MOST RELEVANT items for achieving the stated goal.

SELECTION CRITERIA (prioritize in order):
1. **Security-Critical**: APIs/functions related to crypto, network, file access, registry, process manipulation
2. **Suspicious Patterns**: Obfuscation, anti-debug, packing, encoding, unusual strings
3. **Entry Points**: Main functions, WinMain, DllMain, exported functions
4. **Goal-Specific**: Items directly mentioned or implied by the user's goal
5. **Cross-References**: Items that appeared in previous tool results

OUTPUT FORMAT:
Return ONLY a JSON object with the same structure as the original result, containing the top {max_items} items.
- If the result is a list, return a filtered list
- If the result is a dict with an 'items' or similar array, return the dict with filtered array
- Preserve the original item structure exactly

NO explanations. ONLY the JSON."""

    system_prompt = f"""You are filtering {tool_name} results for relevance.
Output ONLY valid JSON matching the input structure. No markdown. No explanations."""
    
    try:
        self.logger.info(f"🎯 Ranking {item_count} items from {tool_name} to keep top {max_items}")
        
        response = self.ollama.generate(
            prompt=ranking_prompt,
            system_prompt=system_prompt,
            phase="execution"
        )
        
        # Clean markdown if present
        cleaned = response.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            lines = [l for l in lines if not l.startswith("```")]
            cleaned = "\n".join(lines).strip()
        
        # Parse filtered result
        filtered_result = json.loads(cleaned)
        
        # Count filtered items
        filtered_count = 0
        if isinstance(filtered_result, list):
            filtered_count = len(filtered_result)
        elif isinstance(filtered_result, dict):
            if 'items' in filtered_result:
                filtered_count = len(filtered_result.get('items', []))
            elif 'functions' in filtered_result:
                filtered_count = len(filtered_result.get('functions', []))
            elif 'imports' in filtered_result:
                filtered_count = len(filtered_result.get('imports', []))
        
        self.logger.info(f"✅ Ranked: Kept {filtered_count}/{item_count} most relevant items")
        
        return filtered_result
        
    except Exception as e:
        self.logger.warning(f"⚠️ Ranking failed for {tool_name}: {e}. Using original result.")
        return result
