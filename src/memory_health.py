"""
Health check utilities for the memory system.
"""

import os
import logging
import numpy as np
from typing import Dict, Any, List, Optional
import json
from datetime import datetime, timedelta

from .config import BridgeConfig
from .memory_manager import MemoryManager

logger = logging.getLogger(__name__)

class MemoryHealthCheck:
    """Performs health checks on the memory system components."""
    
    def __init__(self, config: BridgeConfig, memory_manager: MemoryManager):
        """
        Initialize the health checker.
        
        Args:
            config: The bridge configuration.
            memory_manager: The memory manager instance.
        """
        self.config = config
        self.memory_manager = memory_manager
        
    def check_configuration(self) -> Dict[str, Any]:
        """
        Check the memory system configuration.
        
        Returns:
            Dictionary with configuration status information.
        """
        config = self.config.session_history
        result = {
            "enabled": config.enabled,
            "storage_path": config.storage_path,
            "storage_exists": os.path.exists(config.storage_path),
            "storage_size": 0,
            "max_sessions": config.max_sessions,
            "auto_summarize": config.auto_summarize,
            "vector_embeddings": {
                "enabled": config.use_vector_embeddings,
                "path": config.vector_db_path,
                "exists": os.path.exists(config.vector_db_path) if config.use_vector_embeddings else False
            }
        }
        
        # Check storage file size
        if result["storage_exists"]:
            try:
                result["storage_size"] = os.path.getsize(config.storage_path)
                result["storage_size_human"] = self._format_bytes(result["storage_size"])
            except Exception as e:
                logger.error(f"Error checking storage file size: {e}")
        
        # Check if CAG is enabled
        result["cag_enabled"] = self.config.cag_enabled
        if self.config.cag_enabled:
            result["cag_knowledge_cache_enabled"] = self.config.cag_knowledge_cache_enabled
            result["cag_session_cache_enabled"] = self.config.cag_session_cache_enabled
            result["cag_token_limit"] = self.config.cag_token_limit
        
        return result
    
    def check_sessions(self) -> Dict[str, Any]:
        """
        Check the status of stored sessions.
        
        Returns:
            Dictionary with session status information.
        """
        result = {
            "total_count": self.memory_manager.get_session_count(),
            "active_session": self.memory_manager.active_session_manager.current_session is not None
        }
        
        if result["active_session"]:
            active = self.memory_manager.active_session_manager.current_session
            result["active_session_info"] = {
                "id": active.session_id,
                "task": active.user_task_description,
                "start_time": active.start_time.isoformat(),
                "tool_calls": len(active.tool_calls)
            }
        
        # Get session statistics
        sessions = self.memory_manager.sessions
        
        # Outcome distribution
        outcomes = {}
        for s in sessions:
            if s.outcome not in outcomes:
                outcomes[s.outcome] = 0
            outcomes[s.outcome] += 1
        result["outcome_distribution"] = outcomes
        
        # Recent activity
        now = datetime.now()
        last_day = [s for s in sessions if s.start_time > (now - timedelta(days=1))]
        last_week = [s for s in sessions if s.start_time > (now - timedelta(days=7))]
        result["recent_activity"] = {
            "last_24h": len(last_day),
            "last_7d": len(last_week)
        }
        
        # Tool usage statistics
        tools_usage = {}
        for s in sessions:
            for tc in s.tool_calls:
                if tc.tool_name not in tools_usage:
                    tools_usage[tc.tool_name] = 0
                tools_usage[tc.tool_name] += 1
        
        # Sort by usage count (descending)
        result["tool_usage"] = dict(sorted(tools_usage.items(), key=lambda x: x[1], reverse=True))
        
        return result
    
    def check_vector_store(self) -> Dict[str, Any]:
        """
        Check the status of the vector store.
        
        Returns:
            Dictionary with vector store status information.
        """
        result = {
            "enabled": self.config.session_history.use_vector_embeddings,
            "vectors_available": False,
            "vector_count": 0,
            "embedding_model": self.memory_manager.embedder.embedding_model
        }
        
        if not result["enabled"]:
            return result
        
        vector_store = self.memory_manager.vector_store
        if vector_store is None:
            return result
        
        result["vectors_available"] = vector_store.vectors is not None and vector_store.vectors.shape[0] > 0
        
        if result["vectors_available"]:
            result["vector_count"] = vector_store.vectors.shape[0]
            result["vector_dimension"] = vector_store.vectors.shape[1]
            result["session_ids"] = vector_store.get_session_ids()
            
            # Calculate some basic statistics about the vectors
            if result["vector_count"] > 0:
                # Mean vector norm
                norms = np.linalg.norm(vector_store.vectors, axis=1)
                result["vector_norm_mean"] = float(np.mean(norms))
                result["vector_norm_std"] = float(np.std(norms))
                
                # Sample vector similarity matrix (first 5 vectors only)
                sample_size = min(5, result["vector_count"])
                if sample_size > 1:
                    sample_vectors = vector_store.vectors[:sample_size]
                    normalized = sample_vectors / np.linalg.norm(sample_vectors, axis=1, keepdims=True)
                    similarity_matrix = np.dot(normalized, normalized.T)
                    # Convert to Python list for JSON serialization
                    result["sample_similarity_matrix"] = [
                        [float(similarity_matrix[i, j]) for j in range(sample_size)]
                        for i in range(sample_size)
                    ]
        
        return result
    
    def check_all(self) -> Dict[str, Any]:
        """
        Run all health checks and return a comprehensive report.
        
        Returns:
            Dictionary with all health check information.
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "configuration": self.check_configuration(),
            "sessions": self.check_sessions(),
            "vector_store": self.check_vector_store()
        }
        
        # Overall health status
        health_issues = []
        
        # Check configuration issues
        if not report["configuration"]["enabled"]:
            health_issues.append("Session history is disabled")
        elif not report["configuration"]["storage_exists"]:
            health_issues.append("Session storage file does not exist")
        
        # Check vector store issues
        if report["configuration"]["vector_embeddings"]["enabled"] and not report["vector_store"]["vectors_available"]:
            health_issues.append("Vector embeddings are enabled but no vectors are available")
        
        report["health_status"] = "healthy" if not health_issues else "issues_detected"
        report["health_issues"] = health_issues
        
        return report
    
    def _format_bytes(self, size_bytes: int) -> str:
        """Format bytes to human-readable string."""
        if size_bytes < 1024:
            return f"{size_bytes} bytes"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
    
    def print_health_report(self) -> None:
        """Print a formatted health report to the console."""
        report = self.check_all()
        
        print("\n" + "="*80)
        print(f" MEMORY SYSTEM HEALTH REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)
        
        # Overall health status
        status_emoji = "✅" if report["health_status"] == "healthy" else "⚠️"
        print(f"\nOverall Status: {status_emoji} {report['health_status'].upper()}")
        
        if report["health_issues"]:
            print("\nDetected Issues:")
            for issue in report["health_issues"]:
                print(f"  - {issue}")
        
        # Configuration
        config = report["configuration"]
        print("\nConfiguration:")
        print(f"  - Session history: {'Enabled ✅' if config['enabled'] else 'Disabled ❌'}")
        print(f"  - Storage path: {config['storage_path']}")
        print(f"  - Storage exists: {'Yes ✅' if config['storage_exists'] else 'No ❌'}")
        if config['storage_exists']:
            print(f"  - Storage size: {config.get('storage_size_human', 'Unknown')}")
        print(f"  - Auto summarize: {'Enabled ✅' if config['auto_summarize'] else 'Disabled ❌'}")
        
        # CAG Configuration
        print(f"\nContext-Aware Generation (CAG):")
        print(f"  - Enabled: {'Yes ✅' if config.get('cag_enabled', False) else 'No ❌'}")
        if config.get('cag_enabled', False):
            print(f"  - Knowledge cache: {'Enabled ✅' if config.get('cag_knowledge_cache_enabled', False) else 'Disabled ❌'}")
            print(f"  - Session cache: {'Enabled ✅' if config.get('cag_session_cache_enabled', False) else 'Disabled ❌'}")
            print(f"  - Token limit: {config.get('cag_token_limit', 'Unknown')}")
        
        # Vector embeddings
        vec_config = config["vector_embeddings"]
        print(f"\nVector Embeddings (RAG):")
        print(f"  - Enabled: {'Yes ✅' if vec_config['enabled'] else 'No ❌'}")
        if vec_config['enabled']:
            print(f"  - Vector DB path: {vec_config['path']}")
            print(f"  - Path exists: {'Yes ✅' if vec_config['exists'] else 'No ❌'}")
        
        # Sessions
        sessions = report["sessions"]
        print(f"\nSessions:")
        print(f"  - Total sessions: {sessions['total_count']}")
        print(f"  - Active session: {'Yes' if sessions['active_session'] else 'No'}")
        
        if sessions['active_session']:
            active = sessions['active_session_info']
            print(f"    - ID: {active['id']}")
            print(f"    - Task: {active['task']}")
            print(f"    - Started: {active['start_time']}")
            print(f"    - Tool calls: {active['tool_calls']}")
        
        # Recent activity
        recent = sessions.get('recent_activity', {})
        if recent:
            print(f"  - Activity last 24h: {recent.get('last_24h', 0)} sessions")
            print(f"  - Activity last 7d: {recent.get('last_7d', 0)} sessions")
        
        # Outcome distribution
        outcomes = sessions.get('outcome_distribution', {})
        if outcomes:
            print("\n  Outcome Distribution:")
            for outcome, count in outcomes.items():
                print(f"    - {outcome}: {count} sessions")
        
        # Tool usage (top 5)
        tools = sessions.get('tool_usage', {})
        if tools:
            print("\n  Top Tool Usage:")
            for i, (tool, count) in enumerate(list(tools.items())[:5]):
                print(f"    - {tool}: {count} calls")
            if len(tools) > 5:
                print(f"    - ... and {len(tools) - 5} more tools")
        
        # Vector store
        vector_store = report["vector_store"]
        print(f"\nVector Store:")
        print(f"  - Enabled: {'Yes ✅' if vector_store['enabled'] else 'No ❌'}")
        
        if vector_store['enabled']:
            print(f"  - Embedding model: {vector_store['embedding_model']}")
            print(f"  - Vectors available: {'Yes ✅' if vector_store['vectors_available'] else 'No ❌'}")
            
            if vector_store['vectors_available']:
                print(f"  - Vector count: {vector_store['vector_count']}")
                print(f"  - Vector dimension: {vector_store['vector_dimension']}")
                print(f"  - Mean vector norm: {vector_store['vector_norm_mean']:.4f}")
                
                # Display sample of session IDs
                session_ids = vector_store.get('session_ids', [])
                if session_ids:
                    sample_size = min(3, len(session_ids))
                    print(f"\n  Sample Session IDs ({sample_size} of {len(session_ids)}):")
                    for i, sid in enumerate(session_ids[:sample_size]):
                        print(f"    - {sid}")
                    if len(session_ids) > sample_size:
                        print(f"    - ... and {len(session_ids) - sample_size} more")
                
                # Omit similarity matrix from console output as it's hard to read
        
        print("\n" + "="*80 + "\n")
        
def run_health_check(config: BridgeConfig, memory_manager: Optional[MemoryManager] = None) -> None:
    """
    Run a health check and display the results.
    
    Args:
        config: The bridge configuration.
        memory_manager: Optional memory manager instance. If None, a new one will be created.
    """
    # Create memory manager if not provided
    if memory_manager is None:
        memory_manager = MemoryManager(config)
    
    # Run health check
    health_checker = MemoryHealthCheck(config, memory_manager)
    health_checker.print_health_report() 