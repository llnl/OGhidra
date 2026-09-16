import os
import sys
import unittest
from unittest.mock import MagicMock, patch

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.config import GhidraMCPConfig  # noqa: E402
from src.ghidra_client import PyGhidraClient  # noqa: E402


class FakeFunction:
    def __init__(self, name: str, entry: str):
        self._name = name
        self._entry = entry

    def getName(self):
        return self._name

    def getEntryPoint(self):
        return self._entry


class FakeFunctionManager:
    def __init__(self, functions):
        self._functions = list(functions)

    def getFunctions(self, _forward):
        return list(self._functions)

    def getFunctionAt(self, _addr):
        return None

    def getFunctionContaining(self, _addr):
        return None


class FakeMemory:
    def __init__(self, contains_addresses):
        self._contains_addresses = set(contains_addresses)

    def contains(self, addr):
        return addr in self._contains_addresses


class FakeAddressSpace:
    def getAddress(self, value):
        return value


class FakeAddressFactory:
    def getDefaultAddressSpace(self):
        return FakeAddressSpace()


class FakeProgram:
    def __init__(self, name: str, functions, contains_addresses):
        self._name = name
        fake_functions = [FakeFunction(name, entry) for name, entry in functions]
        self._function_manager = FakeFunctionManager(fake_functions)
        self._memory = FakeMemory(contains_addresses)
        self._address_factory = FakeAddressFactory()

    def getName(self):
        return self._name

    def getFunctionManager(self):
        return self._function_manager

    def getMemory(self):
        return self._memory

    def getAddressFactory(self):
        return self._address_factory


def make_client() -> PyGhidraClient:
    with patch.object(PyGhidraClient, "_init_pyghidra", lambda self: None):
        return PyGhidraClient(GhidraMCPConfig())


class TestPyGhidraMultiProgram(unittest.TestCase):
    def setUp(self):
        self.client = make_client()
        self.client._project = MagicMock()
        self.client._project.getName.return_value = "demo_project"

    def _register_fake_program(self, key: str, name: str, functions, *, contains_addresses=None):
        program = FakeProgram(name, functions, contains_addresses or set())
        self.client._register_open_program(program, selected_path=key)
        return program

    def test_parse_requested_programs_supports_comma_separated_values(self):
        requested = self.client._parse_requested_programs(" prog1,prog2 , /folder/prog3,prog1 ")
        self.assertEqual(requested, ["prog1", "prog2", "/folder/prog3"])

    def test_select_project_program_paths_resolves_multiple_names_and_paths(self):
        discovered = [
            ("prog1", "/prog1"),
            ("prog2", "/prog2"),
            ("prog3", "/folder/prog3"),
        ]

        selected = self.client._select_project_program_paths(
            discovered,
            ["prog1", "/folder/prog3", "prog2"],
            "demo.gpr",
        )

        self.assertEqual(selected, ["/prog1", "/folder/prog3", "/prog2"])

    def test_select_project_program_paths_opens_all_programs_when_not_specified(self):
        discovered = [
            ("prog1", "/prog1"),
            ("prog2", "/prog2"),
            ("prog3", "/folder/prog3"),
        ]

        selected = self.client._select_project_program_paths(discovered, [], "demo.gpr")

        self.assertEqual(selected, ["/prog1", "/prog2", "/folder/prog3"])

    def test_list_functions_uses_the_active_program_when_multiple_programs_are_open(self):
        self._register_fake_program("/prog1", "prog1", [("func_a", "00401000"), ("func_b", "00402000")])
        self._register_fake_program("/prog2", "prog2", [("func_c", "00501000")])

        result = self.client.list_functions(limit=10)

        self.assertEqual(result[0], "[Total: 2] [Showing: 1-2]")
        self.assertIn("func_a at 00401000", result)
        self.assertIn("func_b at 00402000", result)
        self.assertNotIn("func_c at 00501000", result)

        self.client.instances_use(2)
        result = self.client.list_functions(limit=10)

        self.assertEqual(result[0], "[Total: 1] [Showing: 1-1]")
        self.assertIn("func_c at 00501000", result)
        self.assertNotIn("func_a at 00401000", result)

    def test_instances_use_switches_the_active_program(self):
        prog1 = self._register_fake_program("/prog1", "prog1", [])
        prog2 = self._register_fake_program("/prog2", "prog2", [])

        self.assertIs(self.client._require_program(), prog1)
        message = self.client.instances_use(2)
        self.assertIn("Switched to pyGhidra program 2", message)
        self.assertIs(self.client._require_program(), prog2)
        self.assertEqual(self.client.current_instance_port, 2)
        program_info = self.client.get_current_program_info()
        self.assertEqual(program_info["name"], "prog2")
        self.assertEqual(program_info["program_slot"], "2")

    def test_resolve_function_prefers_the_active_program_when_name_is_ambiguous(self):
        prog1 = self._register_fake_program("/prog1", "prog1", [])
        prog2 = self._register_fake_program("/prog2", "prog2", [])
        func1 = object()
        func2 = object()

        def find_function(name, *, program=None):
            if name != "shared_func":
                return None
            if program is prog1:
                return func1
            if program is prog2:
                return func2
            return None

        self.client._find_function_by_name = MagicMock(side_effect=find_function)

        program_key, program, _info, func, function_name = self.client._resolve_function("shared_func")
        self.assertEqual(program_key, "/prog1")
        self.assertIs(program, prog1)
        self.assertIs(func, func1)
        self.assertEqual(function_name, "shared_func")

        self.client.instances_use(2)
        program_key, program, _info, func, function_name = self.client._resolve_function("shared_func")
        self.assertEqual(program_key, "/prog2")
        self.assertIs(program, prog2)
        self.assertIs(func, func2)
        self.assertEqual(function_name, "shared_func")

        program_key, program, _info, func, function_name = self.client._resolve_function("prog1::shared_func")
        self.assertEqual(program_key, "/prog1")
        self.assertIs(program, prog1)
        self.assertIs(func, func1)
        self.assertEqual(function_name, "shared_func")

    def test_resolve_program_address_prefers_the_active_program_when_address_is_ambiguous(self):
        prog1 = self._register_fake_program("/prog1", "prog1", [], contains_addresses={0x401000})
        prog2 = self._register_fake_program("/prog2", "prog2", [], contains_addresses={0x401000})

        program_key, program, _info, addr, norm_addr = self.client._resolve_program_address("0x401000")
        self.assertEqual(program_key, "/prog1")
        self.assertIs(program, prog1)
        self.assertEqual(addr, 0x401000)
        self.assertEqual(norm_addr, "401000")

        self.client.instances_use(2)
        program_key, program, _info, addr, norm_addr = self.client._resolve_program_address("0x401000")
        self.assertEqual(program_key, "/prog2")
        self.assertIs(program, prog2)
        self.assertEqual(addr, 0x401000)
        self.assertEqual(norm_addr, "401000")

        program_key, program, _info, addr, norm_addr = self.client._resolve_program_address("prog2::0x401000")
        self.assertEqual(program_key, "/prog2")
        self.assertIs(program, prog2)
        self.assertEqual(addr, 0x401000)
        self.assertEqual(norm_addr, "401000")
        self.assertIsNot(program, prog1)


if __name__ == "__main__":
    unittest.main()
