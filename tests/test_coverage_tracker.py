#!/usr/bin/env python3
"""
Unit tests for CoverageTracker — Investigation Area Checklist.

Tests cover the two-tier depth model (encountered → analyzed),
tool classification, prompt formatting, and backward compatibility.
"""

import unittest
from src.coverage_tracker import (
    CoverageTracker, CoverageArea, DEFAULT_CHECKLIST,
    DEPTH_NONE, DEPTH_ENCOUNTERED, DEPTH_ANALYZED,
    ANALYSIS_TOOLS, SURFACE_TOOLS, _max_depth,
)


class TestCoverageTrackerInit(unittest.TestCase):
    """Tests for CoverageTracker initialization."""

    def test_default_checklist_loaded(self):
        """Default checklist has all 9 areas."""
        tracker = CoverageTracker()
        self.assertEqual(len(tracker.areas), 9)

    def test_default_areas_names(self):
        """All expected area names are present."""
        tracker = CoverageTracker()
        expected = {
            "service_management", "process_creation", "privilege_escalation",
            "file_operations", "registry_persistence", "dll_loading",
            "network_comms", "crypto_operations", "input_handling"
        }
        self.assertEqual(set(tracker.areas.keys()), expected)

    def test_custom_checklist(self):
        """Can initialize with a custom checklist."""
        custom = {
            "my_area": {
                "description": "Test area",
                "apis": ["FooW", "BarW"],
                "strings": ["test"],
            }
        }
        tracker = CoverageTracker(checklist=custom)
        self.assertEqual(len(tracker.areas), 1)
        self.assertIn("my_area", tracker.areas)

    def test_all_areas_start_at_depth_none(self):
        """All areas start with depth='none'."""
        tracker = CoverageTracker()
        for area in tracker.areas.values():
            self.assertEqual(area.depth, DEPTH_NONE)
            self.assertFalse(area.covered)  # backward-compat property
            self.assertIsNone(area.covered_by)


class TestDepthHelpers(unittest.TestCase):
    """Tests for depth utility functions."""

    def test_max_depth_same(self):
        self.assertEqual(_max_depth(DEPTH_NONE, DEPTH_NONE), DEPTH_NONE)

    def test_max_depth_encounter_beats_none(self):
        self.assertEqual(_max_depth(DEPTH_NONE, DEPTH_ENCOUNTERED), DEPTH_ENCOUNTERED)
        self.assertEqual(_max_depth(DEPTH_ENCOUNTERED, DEPTH_NONE), DEPTH_ENCOUNTERED)

    def test_max_depth_analyzed_beats_encountered(self):
        self.assertEqual(_max_depth(DEPTH_ENCOUNTERED, DEPTH_ANALYZED), DEPTH_ANALYZED)
        self.assertEqual(_max_depth(DEPTH_ANALYZED, DEPTH_ENCOUNTERED), DEPTH_ANALYZED)

    def test_max_depth_analyzed_beats_none(self):
        self.assertEqual(_max_depth(DEPTH_NONE, DEPTH_ANALYZED), DEPTH_ANALYZED)


class TestCoverageAreaBackwardCompat(unittest.TestCase):
    """Tests that the .covered property still works for backward compat."""

    def test_covered_property_reads_depth(self):
        area = CoverageArea(name="test", description="test")
        self.assertFalse(area.covered)
        area.depth = DEPTH_ENCOUNTERED
        self.assertFalse(area.covered)  # encountered != analyzed
        area.depth = DEPTH_ANALYZED
        self.assertTrue(area.covered)

    def test_covered_setter_sets_depth(self):
        area = CoverageArea(name="test", description="test")
        area.covered = True
        self.assertEqual(area.depth, DEPTH_ANALYZED)
        area.covered = False
        self.assertEqual(area.depth, DEPTH_NONE)


class TestCoverageTrackerMarking(unittest.TestCase):
    """Tests for manual and automatic coverage marking."""

    def test_mark_covered_default_depth(self):
        """mark_covered defaults to 'analyzed' depth."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "decompile_function", "Found OpenServiceW")

        area = tracker.areas["service_management"]
        self.assertEqual(area.depth, DEPTH_ANALYZED)
        self.assertTrue(area.covered)
        self.assertEqual(area.covered_by, "decompile_function")
        self.assertEqual(area.result_summary, "Found OpenServiceW")

    def test_mark_covered_explicit_encountered(self):
        """mark_covered with depth='encountered' sets encountered level."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "list_imports", "Saw APIs",
                             depth=DEPTH_ENCOUNTERED)
        area = tracker.areas["service_management"]
        self.assertEqual(area.depth, DEPTH_ENCOUNTERED)
        self.assertFalse(area.covered)  # encountered is NOT "covered"

    def test_mark_covered_depth_only_increases(self):
        """Depth should never decrease on subsequent marks."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "decompile_function",
                             depth=DEPTH_ANALYZED)
        # Try to downgrade to encountered
        tracker.mark_covered("service_management", "list_imports",
                             depth=DEPTH_ENCOUNTERED)
        self.assertEqual(tracker.areas["service_management"].depth, DEPTH_ANALYZED)

    def test_mark_nonexistent_area(self):
        """Marking a nonexistent area does not raise."""
        tracker = CoverageTracker()
        tracker.mark_covered("nonexistent", "tool", "summary")
        # Should not crash

    # ── Auto-marking with two-tier depth ──

    def test_auto_mark_surface_tool_sets_encountered(self):
        """Surface tools (list_imports) set depth to 'encountered', not 'analyzed'."""
        tracker = CoverageTracker()
        result = '["CreateServiceW -> EXTERNAL:0001", "OpenServiceW -> EXTERNAL:0002"]'

        newly_analyzed = tracker.auto_mark_from_result(
            tool_name="list_imports",
            tool_params={"offset": "0"},
            result=result
        )

        # list_imports is a SURFACE_TOOL → depth should be "encountered"
        area = tracker.areas["service_management"]
        self.assertEqual(area.depth, DEPTH_ENCOUNTERED)
        self.assertFalse(area.covered)  # NOT fully analyzed yet

        # Return value only includes newly "analyzed" areas
        self.assertNotIn("service_management", newly_analyzed)

    def test_auto_mark_analysis_tool_sets_analyzed(self):
        """Analysis tools (decompile) set depth to 'analyzed'."""
        tracker = CoverageTracker()
        result = "void service_func() { CreateServiceW(...); OpenServiceW(...); }"

        newly_analyzed = tracker.auto_mark_from_result(
            tool_name="decompile_function_by_address",
            tool_params={"address": "0x00401000"},
            result=result
        )

        area = tracker.areas["service_management"]
        self.assertEqual(area.depth, DEPTH_ANALYZED)
        self.assertTrue(area.covered)
        self.assertIn("service_management", newly_analyzed)

    def test_auto_mark_surface_then_analysis_upgrades(self):
        """Surface encounter followed by analysis tool upgrades to 'analyzed'."""
        tracker = CoverageTracker()

        # Step 1: list_imports finds CreateServiceW → encountered
        tracker.auto_mark_from_result(
            "list_imports", {}, "CreateServiceW found"
        )
        self.assertEqual(tracker.areas["service_management"].depth, DEPTH_ENCOUNTERED)

        # Step 2: decompile finds CreateServiceW in code → analyzed
        newly = tracker.auto_mark_from_result(
            "decompile_function_by_address", {},
            "void f() { CreateServiceW(hSCManager, ...); }"
        )
        self.assertEqual(tracker.areas["service_management"].depth, DEPTH_ANALYZED)
        self.assertIn("service_management", newly)

    def test_auto_mark_string_match_surface_tool(self):
        """String patterns via surface tools also set 'encountered'."""
        tracker = CoverageTracker()
        result = 'Found string: "SYSTEM\\CurrentControlSet\\Services\\MyService"'

        newly_analyzed = tracker.auto_mark_from_result(
            tool_name="search_strings_in_binary",
            tool_params={"filter": "service"},
            result=result
        )

        # search_strings_in_binary is a surface tool
        area = tracker.areas["service_management"]
        self.assertEqual(area.depth, DEPTH_ENCOUNTERED)
        # Not in newly_analyzed because it's only encountered
        self.assertNotIn("service_management", newly_analyzed)

    def test_auto_mark_xrefs_sets_analyzed(self):
        """get_xrefs_to is an analysis tool — should set 'analyzed'."""
        tracker = CoverageTracker()
        result = "CreateProcessW is called from FUN_00401234, FUN_00405678"

        newly = tracker.auto_mark_from_result(
            "get_xrefs_to", {"name": "CreateProcessW"}, result
        )
        self.assertEqual(tracker.areas["process_creation"].depth, DEPTH_ANALYZED)
        self.assertIn("process_creation", newly)

    def test_auto_mark_multiple_areas_at_once(self):
        """Multiple areas can be marked in a single result."""
        tracker = CoverageTracker()
        result = 'CreateProcessW, LoadLibraryExW, AdjustTokenPrivileges, RegOpenKeyExW'

        newly_analyzed = tracker.auto_mark_from_result(
            tool_name="decompile_function_by_address",
            tool_params={},
            result=result
        )

        # decompile is analysis tool → all areas should be ANALYZED
        self.assertGreaterEqual(len(newly_analyzed), 4)
        self.assertIn("process_creation", newly_analyzed)
        self.assertIn("dll_loading", newly_analyzed)
        self.assertIn("privilege_escalation", newly_analyzed)
        self.assertIn("registry_persistence", newly_analyzed)

    def test_already_analyzed_not_re_reported(self):
        """Already-analyzed areas are not reported again."""
        tracker = CoverageTracker()
        result = "CreateProcessW found"

        covered1 = tracker.auto_mark_from_result(
            "decompile_function_by_address", {}, result
        )
        covered2 = tracker.auto_mark_from_result(
            "decompile_function_by_address", {}, result
        )

        self.assertIn("process_creation", covered1)
        self.assertNotIn("process_creation", covered2)

    def test_unknown_tool_treated_as_analysis(self):
        """Unknown tools are conservatively treated as analysis tools."""
        tracker = CoverageTracker()
        result = "CreateProcessW call at 0x401000"

        newly = tracker.auto_mark_from_result(
            "some_unknown_tool", {}, result
        )
        self.assertEqual(tracker.areas["process_creation"].depth, DEPTH_ANALYZED)
        self.assertIn("process_creation", newly)

    def test_no_match_returns_empty(self):
        """No matches returns empty list."""
        tracker = CoverageTracker()
        result = "Nothing interesting here at all"

        newly_analyzed = tracker.auto_mark_from_result("some_tool", {}, result)
        self.assertEqual(len(newly_analyzed), 0)


class TestCoverageTrackerQueries(unittest.TestCase):
    """Tests for querying coverage state."""

    def test_get_uncovered_initially_all(self):
        """All areas are uncovered initially."""
        tracker = CoverageTracker()
        uncovered = tracker.get_uncovered()
        self.assertEqual(len(uncovered), 9)

    def test_get_uncovered_includes_encountered(self):
        """get_uncovered includes encountered areas (they need deeper analysis)."""
        tracker = CoverageTracker()
        tracker.auto_mark_from_result("list_imports", {}, "CreateProcessW found")

        uncovered = tracker.get_uncovered()
        uncovered_names = [a.name for a in uncovered]
        # process_creation is "encountered" but still shows as uncovered
        self.assertIn("process_creation", uncovered_names)
        self.assertEqual(len(uncovered), 9)  # Nothing fully analyzed yet

    def test_get_uncovered_excludes_analyzed(self):
        """get_uncovered excludes analyzed areas."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "decompile_function")
        uncovered = tracker.get_uncovered()
        uncovered_names = [a.name for a in uncovered]
        self.assertNotIn("service_management", uncovered_names)
        self.assertEqual(len(uncovered), 8)

    def test_get_covered(self):
        """Covered list returns only analyzed areas."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "tool")
        tracker.mark_covered("network_comms", "tool")
        covered = tracker.get_covered()
        self.assertEqual(len(covered), 2)

    def test_get_encountered(self):
        """get_encountered returns only 'encountered' depth areas."""
        tracker = CoverageTracker()
        tracker.auto_mark_from_result("list_imports", {}, "CreateProcessW found")
        tracker.mark_covered("service_management", "decompile_function")

        encountered = tracker.get_encountered()
        self.assertEqual(len(encountered), 1)
        self.assertEqual(encountered[0].name, "process_creation")

    def test_coverage_ratio_zero(self):
        """Coverage ratio is 0 when nothing analyzed."""
        tracker = CoverageTracker()
        self.assertAlmostEqual(tracker.coverage_ratio(), 0.0)

    def test_coverage_ratio_ignores_encountered(self):
        """Coverage ratio only counts 'analyzed', not 'encountered'."""
        tracker = CoverageTracker()
        # Mark everything as encountered via surface tool
        tracker.auto_mark_from_result(
            "list_imports", {},
            "CreateProcessW CreateServiceW AdjustTokenPrivileges "
            "CreateFileW RegOpenKeyExW LoadLibraryW connect CryptEncrypt"
        )
        # All areas encountered but ratio should still be 0
        self.assertAlmostEqual(tracker.coverage_ratio(), 0.0)

    def test_coverage_ratio_full(self):
        """Coverage ratio is 1.0 when all analyzed."""
        tracker = CoverageTracker()
        for name in list(tracker.areas.keys()):
            tracker.mark_covered(name, "tool")
        self.assertAlmostEqual(tracker.coverage_ratio(), 1.0)

    def test_coverage_ratio_partial(self):
        """Coverage ratio reflects partial analyzed coverage."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "tool")
        tracker.mark_covered("network_comms", "tool")
        self.assertAlmostEqual(tracker.coverage_ratio(), 2 / 9)

    def test_coverage_ratio_empty_checklist(self):
        """Coverage ratio is 1.0 for empty checklist (nothing to investigate)."""
        tracker = CoverageTracker(checklist={})
        self.assertAlmostEqual(tracker.coverage_ratio(), 1.0)


class TestCoverageTrackerFormatting(unittest.TestCase):
    """Tests for prompt formatting."""

    def test_format_contains_header(self):
        """Format output starts with header."""
        tracker = CoverageTracker()
        output = tracker.format_for_prompt()
        self.assertIn("## Investigation Coverage", output)

    def test_format_shows_not_investigated(self):
        """Format shows 'Not Yet Investigated' for depth=none areas."""
        tracker = CoverageTracker()
        output = tracker.format_for_prompt()
        self.assertIn("Not Yet Investigated", output)
        self.assertIn("service_management", output)

    def test_format_shows_encountered_tier(self):
        """Format shows 'Encountered' tier for depth=encountered areas."""
        tracker = CoverageTracker()
        tracker.auto_mark_from_result("list_imports", {}, "CreateProcessW found")
        output = tracker.format_for_prompt()
        self.assertIn("Encountered (needs deeper analysis)", output)
        self.assertIn("process_creation", output)
        self.assertIn("NOT decompiled", output)

    def test_format_shows_analyzed_tier(self):
        """Format shows 'Fully Analyzed' for depth=analyzed areas."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "decompile_function", "Found APIs")
        output = tracker.format_for_prompt()
        self.assertIn("Fully Analyzed", output)
        self.assertIn("service_management", output)
        self.assertIn("Found APIs", output)

    def test_format_shows_progress(self):
        """Format shows progress count with 'fully analyzed' wording."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "tool")
        output = tracker.format_for_prompt()
        self.assertIn("1/9", output)
        self.assertIn("fully analyzed", output)

    def test_format_uncovered_has_api_hints(self):
        """Uncovered areas include API name hints."""
        tracker = CoverageTracker()
        output = tracker.format_for_prompt()
        self.assertIn("CreateServiceW", output)


class TestCoverageTrackerReset(unittest.TestCase):
    """Tests for reset functionality."""

    def test_reset_clears_all_coverage(self):
        """Reset marks all areas as depth='none'."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "tool", "Found")
        tracker.mark_covered("network_comms", "tool", "Found")

        tracker.reset()

        self.assertEqual(len(tracker.get_covered()), 0)
        self.assertEqual(len(tracker.get_uncovered()), 9)
        self.assertAlmostEqual(tracker.coverage_ratio(), 0.0)

    def test_reset_clears_metadata(self):
        """Reset clears covered_by, result_summary, hits, and depth."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "list_imports", "Found OpenServiceW")
        tracker.areas["service_management"].hits = 5

        tracker.reset()

        area = tracker.areas["service_management"]
        self.assertEqual(area.depth, DEPTH_NONE)
        self.assertFalse(area.covered)
        self.assertIsNone(area.covered_by)
        self.assertIsNone(area.result_summary)
        self.assertEqual(area.hits, 0)

    def test_reset_clears_encountered(self):
        """Reset also clears 'encountered' state."""
        tracker = CoverageTracker()
        tracker.auto_mark_from_result("list_imports", {}, "CreateProcessW found")
        self.assertEqual(tracker.areas["process_creation"].depth, DEPTH_ENCOUNTERED)

        tracker.reset()
        self.assertEqual(tracker.areas["process_creation"].depth, DEPTH_NONE)


class TestDefaultChecklists(unittest.TestCase):
    """Tests that DEFAULT_CHECKLIST has sensible content."""

    def test_each_area_has_apis(self):
        """Each area defines at least one API to search for."""
        for name, spec in DEFAULT_CHECKLIST.items():
            self.assertGreater(len(spec.get("apis", [])), 0,
                             f"Area '{name}' has no APIs defined")

    def test_each_area_has_strings(self):
        """Each area defines at least one string to search for."""
        for name, spec in DEFAULT_CHECKLIST.items():
            self.assertGreater(len(spec.get("strings", [])), 0,
                             f"Area '{name}' has no strings defined")

    def test_each_area_has_description(self):
        """Each area has a non-empty description."""
        for name, spec in DEFAULT_CHECKLIST.items():
            self.assertTrue(len(spec.get("description", "")) > 0,
                          f"Area '{name}' has no description")

    def test_service_management_has_key_apis(self):
        """Service management area includes critical service APIs."""
        apis = DEFAULT_CHECKLIST["service_management"]["apis"]
        self.assertIn("CreateServiceW", apis)
        self.assertIn("OpenServiceW", apis)
        self.assertIn("OpenSCManagerW", apis)

    def test_service_management_has_dispatcher(self):
        """Service management includes StartServiceCtrlDispatcher (was missing)."""
        apis = DEFAULT_CHECKLIST["service_management"]["apis"]
        self.assertTrue(
            any("StartServiceCtrlDispatcher" in api for api in apis),
            "StartServiceCtrlDispatcher should be in service_management APIs"
        )

    def test_service_management_has_handler(self):
        """Service management includes RegisterServiceCtrlHandler."""
        apis = DEFAULT_CHECKLIST["service_management"]["apis"]
        self.assertTrue(
            any("RegisterServiceCtrlHandler" in api for api in apis),
            "RegisterServiceCtrlHandler should be in service_management APIs"
        )

    def test_privilege_escalation_has_key_apis(self):
        """Privilege escalation area includes token manipulation APIs."""
        apis = DEFAULT_CHECKLIST["privilege_escalation"]["apis"]
        self.assertIn("AdjustTokenPrivileges", apis)
        self.assertIn("OpenProcessToken", apis)

    def test_registry_has_query_api(self):
        """Registry persistence includes RegQueryValueExW."""
        apis = DEFAULT_CHECKLIST["registry_persistence"]["apis"]
        self.assertIn("RegQueryValueExW", apis)


class TestToolClassification(unittest.TestCase):
    """Tests that tool classification sets are correct."""

    def test_analysis_tools_include_decompile(self):
        self.assertIn("decompile_function", ANALYSIS_TOOLS)
        self.assertIn("decompile_function_by_address", ANALYSIS_TOOLS)

    def test_analysis_tools_include_xrefs(self):
        self.assertIn("get_xrefs_to", ANALYSIS_TOOLS)
        self.assertIn("get_xrefs_from", ANALYSIS_TOOLS)

    def test_surface_tools_include_list_imports(self):
        self.assertIn("list_imports", SURFACE_TOOLS)
        self.assertIn("list_exports", SURFACE_TOOLS)

    def test_no_overlap(self):
        """Analysis and surface tool sets should not overlap."""
        overlap = ANALYSIS_TOOLS & SURFACE_TOOLS
        self.assertEqual(len(overlap), 0,
                        f"Tools in both sets: {overlap}")


class TestInputHandlingArea(unittest.TestCase):
    """Tests for the new input_handling coverage area."""

    def test_input_handling_exists(self):
        """input_handling area is present in DEFAULT_CHECKLIST."""
        self.assertIn("input_handling", DEFAULT_CHECKLIST)

    def test_input_handling_has_network_apis(self):
        """input_handling includes key network input APIs."""
        apis = DEFAULT_CHECKLIST["input_handling"]["apis"]
        self.assertIn("recv", apis)
        self.assertIn("accept", apis)
        self.assertIn("bind", apis)

    def test_input_handling_has_http_strings(self):
        """input_handling includes HTTP protocol strings."""
        strings = DEFAULT_CHECKLIST["input_handling"]["strings"]
        self.assertIn("GET", strings)
        self.assertIn("POST", strings)
        self.assertIn("HTTP", strings)

    def test_input_handling_auto_marks_from_recv(self):
        """auto_mark_from_result detects recv in import listing."""
        tracker = CoverageTracker()
        tracker.auto_mark_from_result(
            "list_imports", {}, "recv @ 00404500"
        )
        area = tracker.areas["input_handling"]
        self.assertEqual(area.depth, DEPTH_ENCOUNTERED)

    def test_file_operations_expanded(self):
        """file_operations has expanded APIs (CreateFileA, ReadFile, WriteFile)."""
        apis = DEFAULT_CHECKLIST["file_operations"]["apis"]
        self.assertIn("CreateFileA", apis)
        self.assertIn("ReadFile", apis)
        self.assertIn("WriteFile", apis)

    def test_file_operations_has_traversal_strings(self):
        """file_operations includes directory traversal strings."""
        strings = DEFAULT_CHECKLIST["file_operations"]["strings"]
        self.assertIn("..", strings)
        self.assertIn("../", strings)


class TestDiscoveryCache(unittest.TestCase):
    """Tests for the DiscoveryCache class."""

    def test_empty_cache(self):
        from src.models.memory import DiscoveryCache
        cache = DiscoveryCache()
        self.assertTrue(cache.is_empty())
        self.assertEqual(cache.format_for_prompt(), "")

    def test_store_imports(self):
        from src.models.memory import DiscoveryCache
        cache = DiscoveryCache()
        cache.store_imports(["CreateProcessW", "recv", "send"])
        self.assertFalse(cache.is_empty())
        self.assertTrue(cache.has_imports())
        self.assertEqual(len(cache.imports), 3)

    def test_store_imports_deduplication(self):
        from src.models.memory import DiscoveryCache
        cache = DiscoveryCache()
        cache.store_imports(["CreateProcessW", "recv"])
        cache.store_imports(["recv", "send"])  # recv is duplicate
        self.assertEqual(len(cache.imports), 3)

    def test_store_exports(self):
        from src.models.memory import DiscoveryCache
        cache = DiscoveryCache()
        cache.store_exports(["DllMain", "Initialize"])
        self.assertTrue(cache.has_exports())

    def test_store_strings(self):
        from src.models.memory import DiscoveryCache
        cache = DiscoveryCache()
        cache.store_strings("http", ["GET /index.html", "HTTP/1.0 200 OK"])
        self.assertTrue(cache.has_strings("http"))
        self.assertFalse(cache.has_strings("cmd"))

    def test_store_strings_deduplication(self):
        from src.models.memory import DiscoveryCache
        cache = DiscoveryCache()
        cache.store_strings("http", ["GET /index.html"])
        cache.store_strings("http", ["GET /index.html", "POST /upload"])
        self.assertEqual(len(cache.strings["http"]), 2)

    def test_store_functions(self):
        from src.models.memory import DiscoveryCache
        cache = DiscoveryCache()
        cache.store_functions(["FUN_00401000", "FUN_00402000"], total=200)
        self.assertTrue(cache.has_functions())
        self.assertEqual(cache.total_functions, 200)

    def test_format_for_prompt_with_data(self):
        from src.models.memory import DiscoveryCache
        cache = DiscoveryCache()
        cache.store_imports(["CreateProcessW", "recv"])
        cache.store_strings("http", ["GET /index.html"])
        output = cache.format_for_prompt()
        self.assertIn("Binary Discovery", output)
        self.assertIn("do NOT re-call", output)
        self.assertIn("Imports (2 total)", output)
        self.assertIn("CreateProcessW", output)
        self.assertIn("Strings", output)

    def test_format_for_prompt_max_imports(self):
        from src.models.memory import DiscoveryCache
        cache = DiscoveryCache()
        imports = [f"API_{i}" for i in range(50)]
        cache.store_imports(imports)
        output = cache.format_for_prompt(max_imports=10)
        self.assertIn("40 more imports", output)


if __name__ == "__main__":
    unittest.main()
