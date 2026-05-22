#!/usr/bin/env python3
"""
Lead Tracker — Prioritized Investigation Queue
-----------------------------------------------
Tracks investigation leads to ensure high-priority findings are followed up
before moving to new areas. Prevents the "breadth-over-depth" failure mode.
"""

import logging
from dataclasses import dataclass
from typing import List, Optional, Set
import re

logger = logging.getLogger(__name__)


@dataclass
class Lead:
    """A single investigation lead."""

    description: str
    priority: str  # HIGH, MEDIUM, LOW
    source_address: Optional[str] = None
    status: str = "new"  # new, in_progress, completed, abandoned

    def __str__(self):
        addr_str = f" @ {self.source_address}" if self.source_address else ""
        return f"[{self.priority}] {self.description}{addr_str}"


class LeadTracker:
    """
    Manages a queue of investigation leads with priority sorting.
    """

    def __init__(self):
        self.leads: List[Lead] = []
        self.seen_leads: Set[str] = set()  # To prevent duplicates

    def reset(self):
        """Reset the tracker state, clearing all leads."""
        self.leads = []
        self.seen_leads = set()

    def add_lead(self, description: str, priority: str = "MEDIUM", address: str = None) -> bool:
        """
        Add a new lead if it hasn't been seen before.
        Returns True if added, False if duplicate.
        """
        # Normalize priority
        priority = priority.upper()
        if priority not in ["HIGH", "MEDIUM", "LOW"]:
            priority = "MEDIUM"

        # Create unique signature
        sig = f"{priority}:{description}:{address or ''}"
        if sig in self.seen_leads:
            return False

        self.seen_leads.add(sig)
        self.leads.append(Lead(description, priority, address))
        # Sort by priority (HIGH > MEDIUM > LOW)
        self._sort_leads()
        return True

    def _sort_leads(self):
        """Sort leads by priority: HIGH -> MEDIUM -> LOW."""
        priority_map = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        self.leads.sort(key=lambda x: priority_map.get(x.priority, 1))

    def parse_analysis_dump(self, analysis_content: str) -> int:
        """
        Parse 'investigation_leads' section from AI analysis dump.
        Returns number of new leads added.
        """
        count = 0
        try:
            # Simple regex to find the JSON-like structure or markdown list
            # Matching robust patterns from the dump
            # Example: - [HIGH] 0x401000: Call to AdjustTokenPrivileges...

            # Pattern for markdown style leads in "Cycle Conclusions"
            md_pattern = r"-\s*\[(HIGH|MEDIUM|LOW)\]\s*(0x[0-9a-fA-F]+)?[:\s]*(.*?)(?:\n|$)"

            matches = re.finditer(md_pattern, analysis_content)
            for m in matches:
                prio = m.group(1)
                addr = m.group(2)
                desc = m.group(3).strip()
                if self.add_lead(desc, prio, addr):
                    count += 1

        except Exception as e:
            logger.error(f"Error parsing leads from dump: {e}")

        return count

    def get_active_leads(self, limit: int = 3) -> List[Lead]:
        """Get top N active (new/in_progress) leads."""
        active = [l for l in self.leads if l.status in ["new", "in_progress"]]
        return active[:limit]

    def mark_completed(self, description_partial: str):
        """Mark a lead as completed by partial description match."""
        for lead in self.leads:
            if description_partial.lower() in lead.description.lower():
                lead.status = "completed"

    def format_for_prompt(self) -> str:
        """Format active leads for the agent prompt."""
        active = self.get_active_leads(5)  # Show top 5
        if not active:
            return ""

        lines = ["## 🔍 Active Investigation Leads (Prioritized)"]
        lines.append("You MUST address all HIGH priority leads before starting new searches.")

        for lead in active:
            icon = "🔴" if lead.priority == "HIGH" else "bf"
            lines.append(
                f"- {icon} **{lead.priority}**: {lead.description} {f'(Addr: {lead.source_address})' if lead.source_address else ''}"
            )

        return "\n".join(lines)
