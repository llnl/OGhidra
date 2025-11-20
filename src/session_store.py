"""
Session history storage and retrieval.
"""

import json
import os
import datetime
from typing import List, Dict, Any, Optional

from .memory_models import SessionRecord, ToolCallRecord

class SessionHistoryStore:
    def __init__(self, storage_path: str = "session_history.jsonl"):
        self.storage_path = storage_path
        # Ensure the directory for the storage path exists
        storage_dir = os.path.dirname(self.storage_path)
        if storage_dir and not os.path.exists(storage_dir):
            os.makedirs(storage_dir, exist_ok=True)

    def save_session(self, record: SessionRecord):
        """Appends a session record to the storage file."""
        if record.outcome == "in_progress" and record.end_time is None:
            record.end_time = datetime.datetime.utcnow()

        with open(self.storage_path, "a", encoding="utf-8") as f:
            f.write(record.model_dump_json())
            f.write("\n")

    def load_all_sessions(self) -> List[SessionRecord]:
        """Loads all session records from the storage file."""
        if not os.path.exists(self.storage_path):
            return []
        
        records = []
        with open(self.storage_path, "r", encoding="utf-8") as f:
            for line_number, line in enumerate(f, 1):
                if line.strip():
                    try:
                        data = json.loads(line)
                        records.append(SessionRecord.model_validate(data))
                    except json.JSONDecodeError as e:
                        print(f"Warning: Skipping malformed JSON line {line_number} in '{self.storage_path}': {e}")
                    except Exception as e:
                        print(f"Warning: Skipping record on line {line_number} due to data conversion error: {e}")
        return records
    
    def get_session_by_id(self, session_id: str) -> Optional[SessionRecord]:
        """Retrieves a specific session by its ID."""
        for session in self.load_all_sessions():
            if session.session_id == session_id:
                return session
        return None 