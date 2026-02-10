"""
Tests for ExecutionGatekeeper — Interactive execution gate.

Verifies:
    1. Artifact detection triggers PAUSE on critical patterns
    2. Doom-loop detection triggers PAUSE on repetition
    3. High-risk tool gate triggers PAUSE when enabled
    4. All gates disabled returns CONTINUE
    5. No false positives on benign results
    6. Feedback injection/consumption
    7. Reset clears state
"""

import unittest
from unittest.mock import MagicMock
from src.models.memory import ExecutionSignal, ExecutionGate, ToolExecution
from src.execution_gate import ExecutionGatekeeper


class MockConfig:
    """Minimal config mock for gatekeeper tests."""
    def __init__(self, **overrides):
        defaults = {
            'execution_gate_enabled': True,
            'gate_on_artifact': True,
            'gate_on_repetition': True,
            'gate_repetition_threshold': 3,
            'gate_on_high_risk_tool': False,
            'gate_auto_resume_timeout': 0,
        }
        defaults.update(overrides)
        for k, v in defaults.items():
            setattr(self, k, v)


class TestArtifactDetection(unittest.TestCase):
    """Test gate_on_artifact: critical pattern matching in tool results."""

    def setUp(self):
        self.gate = ExecutionGatekeeper(MockConfig())

    def test_privilege_escalation_detected(self):
        """SeTakeOwnershipPrivilege should trigger PAUSE."""
        result = "Found token with SeTakeOwnershipPrivilege enabled"
        signal = self.gate.check_after_execution("decompile_function", result, [])
        self.assertEqual(signal, ExecutionSignal.PAUSE)
        gate = self.gate.get_gate_reason()
        self.assertIsNotNone(gate)
        self.assertEqual(gate.trigger, "artifact")
        self.assertIn("SeTakeOwnershipPrivilege", gate.reason)

    def test_debug_privilege_detected(self):
        """SeDebugPrivilege should trigger PAUSE."""
        result = "OpenProcessToken followed by AdjustTokenPrivileges to set SeDebugPrivilege"
        signal = self.gate.check_after_execution("decompile_function", result, [])
        self.assertEqual(signal, ExecutionSignal.PAUSE)

    def test_crypto_api_detected(self):
        """CryptEncrypt / BCryptDecrypt should trigger PAUSE."""
        result = "call to BCryptDecrypt(handle, encrypted_buffer, ...)"
        signal = self.gate.check_after_execution("decompile_function", result, [])
        self.assertEqual(signal, ExecutionSignal.PAUSE)
        self.assertIn("Cryptographic", self.gate.get_gate_reason().reason)

    def test_hardcoded_ip_url_detected(self):
        """Hardcoded IP URL (possible C2) should trigger PAUSE."""
        result = 'char* c2_url = "http://192.168.1.100/beacon";'
        signal = self.gate.check_after_execution("list_strings", result, [])
        self.assertEqual(signal, ExecutionSignal.PAUSE)
        self.assertIn("C2", self.gate.get_gate_reason().reason)

    def test_shellcode_pattern_detected(self):
        """WriteProcessMemory should trigger PAUSE."""
        result = "WriteProcessMemory(hProcess, remoteAddr, shellcode, size, NULL)"
        signal = self.gate.check_after_execution("decompile_function", result, [])
        self.assertEqual(signal, ExecutionSignal.PAUSE)
        self.assertIn("injection", self.gate.get_gate_reason().reason)

    def test_private_key_detected(self):
        """Embedded private key should trigger PAUSE."""
        result = '-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ...'
        signal = self.gate.check_after_execution("list_strings", result, [])
        self.assertEqual(signal, ExecutionSignal.PAUSE)

    def test_benign_result_no_trigger(self):
        """Normal result without critical patterns should return CONTINUE."""
        result = '{"functions": [{"name": "main", "address": "0x401000"}]}'
        signal = self.gate.check_after_execution("list_functions", result, [])
        self.assertEqual(signal, ExecutionSignal.CONTINUE)
        self.assertIsNone(self.gate.get_gate_reason())

    def test_empty_result_no_trigger(self):
        """Empty result should return CONTINUE."""
        signal = self.gate.check_after_execution("list_functions", "", [])
        self.assertEqual(signal, ExecutionSignal.CONTINUE)

    def test_artifact_disabled(self):
        """With gate_on_artifact=False, critical patterns should not trigger."""
        gate = ExecutionGatekeeper(MockConfig(gate_on_artifact=False))
        result = "SeTakeOwnershipPrivilege detected"
        signal = gate.check_after_execution("decompile_function", result, [])
        self.assertEqual(signal, ExecutionSignal.CONTINUE)

    def test_multiple_artifacts_counted(self):
        """Multiple patterns in one result should all be captured in context."""
        result = "AdjustTokenPrivileges then CryptEncrypt then WriteProcessMemory"
        signal = self.gate.check_after_execution("decompile_function", result, [])
        self.assertEqual(signal, ExecutionSignal.PAUSE)
        gate = self.gate.get_gate_reason()
        self.assertGreater(gate.context["total_matches"], 1)


class TestDoomLoopDetection(unittest.TestCase):
    """Test gate_on_repetition: doom-loop detection (OpenCode pattern)."""

    def setUp(self):
        self.gate = ExecutionGatekeeper(MockConfig(gate_repetition_threshold=3))

    def test_repetition_triggers_on_threshold(self):
        """Third identical call should trigger PAUSE."""
        params = {"address": "0x401000"}
        # First two calls: fine
        self.assertEqual(
            self.gate.check_before_execution("decompile_function", params, []),
            ExecutionSignal.CONTINUE
        )
        self.assertEqual(
            self.gate.check_before_execution("decompile_function", params, []),
            ExecutionSignal.CONTINUE
        )
        # Third call: doom-loop
        signal = self.gate.check_before_execution("decompile_function", params, [])
        self.assertEqual(signal, ExecutionSignal.PAUSE)
        gate = self.gate.get_gate_reason()
        self.assertEqual(gate.trigger, "repetition")
        self.assertIn("Doom-loop", gate.reason)

    def test_different_params_no_trigger(self):
        """Same tool with different params should NOT trigger."""
        for i in range(5):
            signal = self.gate.check_before_execution(
                "decompile_function", {"address": f"0x40{i}000"}, []
            )
            self.assertEqual(signal, ExecutionSignal.CONTINUE)

    def test_different_tools_no_trigger(self):
        """Different tools with same params should NOT trigger."""
        params = {"address": "0x401000"}
        tools = ["decompile_function", "get_xrefs_to", "list_imports"]
        for tool in tools:
            signal = self.gate.check_before_execution(tool, params, [])
            self.assertEqual(signal, ExecutionSignal.CONTINUE)

    def test_repetition_disabled(self):
        """With gate_on_repetition=False, duplicates should not trigger."""
        gate = ExecutionGatekeeper(MockConfig(gate_on_repetition=False))
        params = {"address": "0x401000"}
        for _ in range(5):
            signal = gate.check_before_execution("decompile_function", params, [])
            self.assertEqual(signal, ExecutionSignal.CONTINUE)

    def test_reset_clears_repetition(self):
        """Reset should clear repetition counts."""
        params = {"address": "0x401000"}
        self.gate.check_before_execution("decompile_function", params, [])
        self.gate.check_before_execution("decompile_function", params, [])
        self.gate.reset()
        # After reset, count starts at 1 again
        signal = self.gate.check_before_execution("decompile_function", params, [])
        self.assertEqual(signal, ExecutionSignal.CONTINUE)


class TestHighRiskToolGate(unittest.TestCase):
    """Test gate_on_high_risk_tool: destructive tool approval."""

    def test_rename_triggers_when_enabled(self):
        """rename_function should trigger PAUSE when gate_on_high_risk_tool=True."""
        gate = ExecutionGatekeeper(MockConfig(gate_on_high_risk_tool=True))
        signal = gate.check_before_execution(
            "rename_function", {"name": "malicious_init"}, []
        )
        self.assertEqual(signal, ExecutionSignal.PAUSE)
        self.assertEqual(gate.get_gate_reason().trigger, "high_risk")

    def test_rename_no_trigger_when_disabled(self):
        """rename_function should NOT trigger when gate_on_high_risk_tool=False (default)."""
        gate = ExecutionGatekeeper(MockConfig(gate_on_high_risk_tool=False))
        signal = gate.check_before_execution(
            "rename_function", {"name": "malicious_init"}, []
        )
        self.assertEqual(signal, ExecutionSignal.CONTINUE)

    def test_safe_tool_no_trigger(self):
        """Non-destructive tools should never trigger high-risk gate."""
        gate = ExecutionGatekeeper(MockConfig(gate_on_high_risk_tool=True))
        signal = gate.check_before_execution(
            "decompile_function", {"address": "0x401000"}, []
        )
        self.assertEqual(signal, ExecutionSignal.CONTINUE)


class TestGateDisabled(unittest.TestCase):
    """Test that all checks return CONTINUE when gate is disabled."""

    def test_all_disabled(self):
        """With execution_gate_enabled=False, nothing should trigger."""
        gate = ExecutionGatekeeper(MockConfig(execution_gate_enabled=False))

        # Pre-exec: high-risk + repetition
        for _ in range(5):
            self.assertEqual(
                gate.check_before_execution("rename_function", {"name": "x"}, []),
                ExecutionSignal.CONTINUE
            )

        # Post-exec: artifact
        self.assertEqual(
            gate.check_after_execution("decompile_function", "SeTakeOwnershipPrivilege", []),
            ExecutionSignal.CONTINUE
        )


class TestFeedback(unittest.TestCase):
    """Test feedback injection/consumption (CorrectedError pattern)."""

    def setUp(self):
        self.gate = ExecutionGatekeeper(MockConfig())

    def test_inject_and_consume(self):
        """Feedback should be stored and cleared on consumption."""
        self.gate.inject_feedback("Focus on crypto imports instead")
        feedback = self.gate.consume_feedback()
        self.assertEqual(feedback, "Focus on crypto imports instead")
        # Second consumption should return None
        self.assertIsNone(self.gate.consume_feedback())

    def test_no_feedback_returns_none(self):
        """consume_feedback without inject should return None."""
        self.assertIsNone(self.gate.consume_feedback())

    def test_reset_clears_feedback(self):
        """Reset should clear pending feedback."""
        self.gate.inject_feedback("test")
        self.gate.reset()
        self.assertIsNone(self.gate.consume_feedback())


class TestReset(unittest.TestCase):
    """Test that reset clears all internal state."""

    def test_full_reset(self):
        gate = ExecutionGatekeeper(MockConfig())
        # Trigger artifact gate
        gate.check_after_execution("test", "SeTakeOwnershipPrivilege", [])
        self.assertIsNotNone(gate.get_gate_reason())
        # Accumulate repetitions
        gate.check_before_execution("decompile_function", {"a": "1"}, [])
        # Inject feedback
        gate.inject_feedback("feedback")

        gate.reset()

        self.assertIsNone(gate.get_gate_reason())
        self.assertIsNone(gate.consume_feedback())
        # Repetition tracker should be cleared (first call returns CONTINUE)
        self.assertEqual(
            gate.check_before_execution("decompile_function", {"a": "1"}, []),
            ExecutionSignal.CONTINUE
        )


if __name__ == '__main__':
    unittest.main()
