
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.bridge import Bridge
from src.config import BridgeConfig, OllamaConfig
from src.models.memory import ToolExecution
from datetime import datetime

class TestPromptConstruction(unittest.TestCase):
    def setUp(self):
        # Mock configuration
        self.config = BridgeConfig()
        self.config.ollama.model = "test-model"
        
        # Initialize bridge with mocks where necessary
        with patch('src.bridge.OllamaClient'), \
             patch('src.bridge.GhidraMCPClient'):
            self.bridge = Bridge(self.config)
            
    def test_batching_instructions_in_system_prompt(self):
        """Verify that batching instructions appear in the system prompt."""
        system_prompt, user_prompt = self.bridge._build_structured_prompt(phase="execution")
        
        print("\n--- System Prompt Batching Check ---")
        if "EXECUTE MULTIPLE TOOLS IN ONE RESPONSE" in system_prompt:
            print("✅ Batching instruction found: 'EXECUTE MULTIPLE TOOLS IN ONE RESPONSE'")
        else:
            print("❌ Batching instruction MISSING!")
            self.fail("Batching instruction missing from system prompt")
            
        if "Capability Mapping" in system_prompt:
            print("✅ Capability First instruction found")
        else:
            print("❌ Capability First instruction MISSING!")
            self.fail("Capability First instruction missing")

    def test_completed_steps_injection(self):
        """Verify that executed tools are injected into the user prompt."""
        # Use correct API for adding messages
        from src.models.memory import MessageRole
        self.bridge.session.add_message(MessageRole.USER, "Show me imports") 
        
        # Add 4 execution records to trigger the slicing logic (buggy if params_display_list used)
        for i in range(4):
            exec_record = ToolExecution(
                tool_name="list_imports",
                parameters={"offset": i*50, "limit": 50},
                result=f"result {i}",
                success=True,
                timestamp=datetime.now()
            )
            self.bridge.session.tool_executions.append(exec_record)
        
        system_prompt, user_prompt = self.bridge._build_structured_prompt(phase="execution")
        
        print("\n--- User Prompt Injection Check ---")
        if "COMPLETED STEPS (DO NOT REPEAT)" in user_prompt:
            print("✅ 'COMPLETED STEPS' section found")
        else:
            print("❌ 'COMPLETED STEPS' section MISSING!")
            self.fail("Completed steps section missing from user prompt")
            
        # Should only show the last 3
        if "offset=150" in user_prompt and "offset=100" in user_prompt:
             print("✅ Executed tool 'list_imports' found in summary")
        else:
             print(f"❌ Executed tool NOT found. User Prompt snippet:\n{user_prompt[-500:]}")
             self.fail("Executed tool list_imports not found in user prompt summary")

    def test_knowledge_injection(self):
        """Verify that knowledge artifacts are injected into the user prompt."""
        # Add a knowledge artifact
        self.bridge.session.add_knowledge("C2_Server", "10.0.0.5", "network")
        
        system_prompt, user_prompt = self.bridge._build_structured_prompt(phase="execution")
        
        if "[network] C2_Server: 10.0.0.5" in user_prompt:
            print("✅ network artifact found in prompt")
        else:
            self.fail("Network artifact missing from prompt")

    def test_artifact_parsing(self):
        """Verify that ARTIFACT: lines are parsed from LLM response."""
        response_text = """
        I found some interesting things.
        ARTIFACT: [network] C2_IP = 192.168.1.100
        Then I found a key.
        ARTIFACT: [crypto] AES_Key = 0xCAFEBABE
        """
        
        print("\n--- Artifact Regex Parsing Check ---")
        self.bridge._parse_and_save_artifacts(response_text)
        
        # Check session knowledge base
        kb = self.bridge.session.knowledge_base
        
        found_c2 = any(k.key == "C2_IP" and k.value == "192.168.1.100" for k in kb)
        found_key = any(k.key == "AES_Key" and k.value == "0xCAFEBABE" for k in kb)
        
        if found_c2:
            print("✅ Parsed C2_IP artifact correctly")
        else:
            self.fail("Failed to parse C2_IP artifact")
            
        if found_key:
            print("✅ Parsed AES_Key artifact correctly")
        else:
            self.fail("Failed to parse AES_Key artifact")

if __name__ == '__main__':
    unittest.main()
