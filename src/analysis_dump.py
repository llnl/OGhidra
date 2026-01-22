"""
Analysis Dump Module for OGhidra

This module captures and saves raw analysis context (tool outputs, COT reasoning,
artifacts) before any truncation or summarization is applied. This allows for
manual review of what data the agent is processing.

The dump file provides visibility into:
- All tool execution results (full, untruncated)
- Chain of thought reasoning
- Artifacts generated during analysis
"""

import logging
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("ollama-ghidra-bridge.analysis_dump")


@dataclass
class DumpEntry:
    """A single entry in the analysis dump."""
    entry_type: str  # 'tool', 'reasoning', 'artifact', 'error'
    timestamp: datetime
    loop_number: int
    step_number: int
    tool_name: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    result: Optional[str] = None
    reasoning: Optional[str] = None
    char_count: int = 0
    was_truncated: bool = False
    truncated_to: int = 0


class AnalysisDumper:
    """
    Captures raw analysis context before truncation for manual review.
    
    Saves all tool outputs, reasoning, and artifacts to a markdown file
    in the logs directory. This provides visibility into context window
    usage and helps identify optimization opportunities.
    """
    
    def __init__(self, logs_dir: str = None):
        """
        Initialize the analysis dumper.
        
        Args:
            logs_dir: Directory to save dump files. Defaults to 'logs' in project root.
        """
        if logs_dir is None:
            # Default to logs directory relative to src
            src_dir = os.path.dirname(os.path.abspath(__file__))
            logs_dir = os.path.join(os.path.dirname(src_dir), "logs")
        
        self.logs_dir = logs_dir
        self.entries: List[DumpEntry] = []
        self.current_loop = 1
        self.current_step = 0
        self.session_start = datetime.now()
        self.goal = ""
        self.plan = ""
        
        # Create logs directory if it doesn't exist
        os.makedirs(self.logs_dir, exist_ok=True)
        
        logger.info(f"AnalysisDumper initialized, will save to: {self.logs_dir}")
    
    def set_goal(self, goal: str) -> None:
        """Set the investigation goal."""
        self.goal = goal
    
    def set_plan(self, plan: str) -> None:
        """Set the execution plan."""
        self.plan = plan
    
    def start_loop(self, loop_number: int) -> None:
        """Mark the start of a new agentic loop."""
        self.current_loop = loop_number
        self.current_step = 0
        logger.debug(f"AnalysisDumper: Starting loop {loop_number}")
    
    def add_execution(self, 
                      tool_name: str, 
                      parameters: Dict[str, Any], 
                      result: str,
                      reasoning: Optional[str] = None,
                      was_truncated: bool = False,
                      truncated_to: int = 0) -> None:
        """
        Add a tool execution to the dump.
        
        Args:
            tool_name: Name of the executed tool
            parameters: Tool parameters
            result: Full, untruncated result
            reasoning: COT reasoning for this execution
            was_truncated: Whether the result was truncated for context
            truncated_to: If truncated, the final character count
        """
        self.current_step += 1
        
        entry = DumpEntry(
            entry_type='tool',
            timestamp=datetime.now(),
            loop_number=self.current_loop,
            step_number=self.current_step,
            tool_name=tool_name,
            parameters=parameters,
            result=result,
            reasoning=reasoning,
            char_count=len(result) if result else 0,
            was_truncated=was_truncated,
            truncated_to=truncated_to
        )
        
        self.entries.append(entry)
        logger.debug(f"Added dump entry: L{self.current_loop}_S{self.current_step} {tool_name} ({entry.char_count} chars)")
    
    def add_reasoning(self, reasoning: str) -> None:
        """Add standalone reasoning/COT to the dump."""
        entry = DumpEntry(
            entry_type='reasoning',
            timestamp=datetime.now(),
            loop_number=self.current_loop,
            step_number=self.current_step,
            reasoning=reasoning,
            char_count=len(reasoning) if reasoning else 0
        )
        self.entries.append(entry)
    
    def add_artifact(self, category: str, key: str, value: str) -> None:
        """Add an artifact to the dump."""
        entry = DumpEntry(
            entry_type='artifact',
            timestamp=datetime.now(),
            loop_number=self.current_loop,
            step_number=self.current_step,
            tool_name=f"{category}:{key}",
            result=value,
            char_count=len(value) if value else 0
        )
        self.entries.append(entry)
    
    def add_error(self, error_msg: str, context: str = "") -> None:
        """Add an error to the dump."""
        entry = DumpEntry(
            entry_type='error',
            timestamp=datetime.now(),
            loop_number=self.current_loop,
            step_number=self.current_step,
            result=f"{error_msg}\nContext: {context}" if context else error_msg,
            char_count=len(error_msg)
        )
        self.entries.append(entry)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the dump."""
        total_chars = sum(e.char_count for e in self.entries)
        tool_entries = [e for e in self.entries if e.entry_type == 'tool']
        truncated_entries = [e for e in tool_entries if e.was_truncated]
        
        return {
            'total_entries': len(self.entries),
            'tool_executions': len(tool_entries),
            'reasoning_entries': len([e for e in self.entries if e.entry_type == 'reasoning']),
            'artifact_entries': len([e for e in self.entries if e.entry_type == 'artifact']),
            'error_entries': len([e for e in self.entries if e.entry_type == 'error']),
            'total_characters': total_chars,
            'estimated_tokens': total_chars // 4,
            'truncated_count': len(truncated_entries),
            'chars_saved_by_truncation': sum(e.char_count - e.truncated_to for e in truncated_entries),
            'loops_completed': self.current_loop,
            'total_steps': self.current_step
        }
    
    def save(self, filename: str = None) -> str:
        """
        Save the dump to a markdown file.
        
        Args:
            filename: Optional custom filename. Defaults to timestamped name.
            
        Returns:
            Path to the saved file.
        """
        if filename is None:
            timestamp = self.session_start.strftime("%Y%m%d_%H%M%S")
            filename = f"analysis_dump_{timestamp}.md"
        
        filepath = os.path.join(self.logs_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            # Header
            f.write("# Analysis Context Dump\n\n")
            f.write(f"**Session Start:** {self.session_start.isoformat()}\n")
            f.write(f"**Dump Generated:** {datetime.now().isoformat()}\n\n")
            
            # Goal and Plan
            if self.goal:
                f.write("## Investigation Goal\n\n")
                f.write(f"{self.goal}\n\n")
            
            if self.plan:
                f.write("## Execution Plan\n\n")
                f.write(f"{self.plan}\n\n")
            
            # Statistics
            stats = self.get_statistics()
            f.write("## Statistics\n\n")
            f.write("| Metric | Value |\n")
            f.write("|--------|-------|\n")
            f.write(f"| Total Entries | {stats['total_entries']} |\n")
            f.write(f"| Tool Executions | {stats['tool_executions']} |\n")
            f.write(f"| Reasoning Entries | {stats['reasoning_entries']} |\n")
            f.write(f"| Artifact Entries | {stats['artifact_entries']} |\n")
            f.write(f"| Error Entries | {stats['error_entries']} |\n")
            f.write(f"| Total Characters | {stats['total_characters']:,} |\n")
            f.write(f"| Estimated Tokens | {stats['estimated_tokens']:,} |\n")
            f.write(f"| Truncated Results | {stats['truncated_count']} |\n")
            f.write(f"| Chars Saved by Truncation | {stats['chars_saved_by_truncation']:,} |\n")
            f.write(f"| Loops Completed | {stats['loops_completed']} |\n")
            f.write(f"| Total Steps | {stats['total_steps']} |\n\n")
            
            # Entries by loop
            current_loop = 0
            for entry in self.entries:
                # New loop header
                if entry.loop_number != current_loop:
                    current_loop = entry.loop_number
                    f.write(f"\n---\n\n## Loop {current_loop}\n\n")
                
                # Entry content
                if entry.entry_type == 'tool':
                    truncation_note = ""
                    if entry.was_truncated:
                        truncation_note = f" ⚠️ *Truncated from {entry.char_count:,} to {entry.truncated_to:,} chars*"
                    
                    f.write(f"### Step {entry.step_number}: `{entry.tool_name}`{truncation_note}\n\n")
                    f.write(f"**Time:** {entry.timestamp.strftime('%H:%M:%S')}\n")
                    f.write(f"**Characters:** {entry.char_count:,}\n\n")
                    
                    if entry.parameters:
                        f.write("**Parameters:**\n```json\n")
                        import json
                        f.write(json.dumps(entry.parameters, indent=2))
                        f.write("\n```\n\n")
                    
                    if entry.reasoning:
                        f.write("**Reasoning:**\n")
                        f.write(f"> {entry.reasoning}\n\n")
                    
                    f.write("**Full Result:**\n```\n")
                    f.write(entry.result or "(no result)")
                    f.write("\n```\n\n")
                
                elif entry.entry_type == 'reasoning':
                    f.write(f"### 💭 Reasoning\n\n")
                    f.write(f"{entry.reasoning}\n\n")
                
                elif entry.entry_type == 'artifact':
                    f.write(f"### 📦 Artifact: `{entry.tool_name}`\n\n")
                    f.write(f"```\n{entry.result}\n```\n\n")
                
                elif entry.entry_type == 'error':
                    f.write(f"### ❌ Error\n\n")
                    f.write(f"```\n{entry.result}\n```\n\n")
        
        logger.info(f"Analysis dump saved to: {filepath}")
        logger.info(f"Stats: {stats['total_entries']} entries, {stats['total_characters']:,} chars, {stats['truncated_count']} truncated")
        
        return filepath
    
    def reset(self) -> None:
        """Reset the dumper for a new session."""
        self.entries.clear()
        self.current_loop = 1
        self.current_step = 0
        self.session_start = datetime.now()
        self.goal = ""
        self.plan = ""
        logger.debug("AnalysisDumper reset")
