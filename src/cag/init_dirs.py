"""
Utility script to initialize directory structures for CAG.
"""

import os
import logging
import shutil
from pathlib import Path

logger = logging.getLogger("ollama-ghidra-bridge.cag.init")

def ensure_cag_directories():
    """
    Ensure that all required directories for CAG exist.
    Creates them if they don't exist.
    """
    # Get the directory where this script is located
    cag_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    
    # Ensure knowledge directory exists
    knowledge_dir = cag_dir / "knowledge"
    os.makedirs(knowledge_dir, exist_ok=True)
    
    # Ensure session cache directory exists
    session_cache_dir = Path("ghidra_session_cache")
    os.makedirs(session_cache_dir, exist_ok=True)
    
    # Ensure knowledge cache directory exists
    knowledge_cache_dir = Path("ghidra_knowledge_cache")
    os.makedirs(knowledge_cache_dir, exist_ok=True)
    
    logger.info(f"CAG directories initialized.")
    
    # Copy default knowledge files if they don't exist in the cache directory
    for filename in ["function_signatures.json", "common_workflows.json"]:
        source_path = knowledge_dir / filename
        dest_path = knowledge_cache_dir / filename
        
        if source_path.exists() and not dest_path.exists():
            try:
                shutil.copy2(source_path, dest_path)
                logger.info(f"Copied default knowledge file: {filename}")
            except Exception as e:
                logger.error(f"Error copying {filename}: {str(e)}")

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    ensure_cag_directories()
    print("CAG directories initialized successfully.") 