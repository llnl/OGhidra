#!/usr/bin/env python3
"""
Unit tests for CoverageTracker — Investigation Area Checklist.
"""

import unittest
from src.coverage_tracker import CoverageTracker, CoverageArea, DEFAULT_CHECKLIST


class TestCoverageTrackerInit(unittest.TestCase):
    """Tests for CoverageTracker initialization."""
    
    def test_default_checklist_loaded(self):
        """Default checklist has all 8 areas."""
        tracker = CoverageTracker()
        self.assertEqual(len(tracker.areas), 8)
    
    def test_default_areas_names(self):
        """All expected area names are present."""
        tracker = CoverageTracker()
        expected = {
            "service_management", "process_creation", "privilege_escalation",
            "file_operations", "registry_persistence", "dll_loading",
            "network_comms", "crypto_operations"
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
    
    def test_all_areas_start_uncovered(self):
        """All areas start with covered=False."""
        tracker = CoverageTracker()
        for area in tracker.areas.values():
            self.assertFalse(area.covered)
            self.assertIsNone(area.covered_by)


class TestCoverageTrackerMarking(unittest.TestCase):
    """Tests for manual and automatic coverage marking."""
    
    def test_mark_covered(self):
        """Mark an area as covered manually."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "list_imports", "Found OpenServiceW")
        
        area = tracker.areas["service_management"]
        self.assertTrue(area.covered)
        self.assertEqual(area.covered_by, "list_imports")
        self.assertEqual(area.result_summary, "Found OpenServiceW")
    
    def test_mark_nonexistent_area(self):
        """Marking a nonexistent area does not raise."""
        tracker = CoverageTracker()
        tracker.mark_covered("nonexistent", "tool", "summary")
        # Should not crash
    
    def test_auto_mark_from_api_in_result(self):
        """Auto-marks area when API name appears in result."""
        tracker = CoverageTracker()
        result = '["CreateServiceW -> EXTERNAL:0001", "OpenServiceW -> EXTERNAL:0002"]'
        
        newly_covered = tracker.auto_mark_from_result(
            tool_name="list_imports",
            tool_params={"offset": "0"},
            result=result
        )
        
        self.assertIn("service_management", newly_covered)
        self.assertTrue(tracker.areas["service_management"].covered)
    
    def test_auto_mark_from_string_in_result(self):
        """Auto-marks area when string pattern appears in result."""
        tracker = CoverageTracker()
        result = 'Found string: "SYSTEM\\CurrentControlSet\\Services\\MyService"'
        
        newly_covered = tracker.auto_mark_from_result(
            tool_name="list_strings",
            tool_params={"filter": "service"},
            result=result
        )
        
        # Should match service_management (has "service" string) and registry_persistence (has "CurrentControlSet")
        self.assertIn("service_management", newly_covered)
    
    def test_auto_mark_from_tool_params(self):
        """Auto-marks when filter param contains a matching string."""
        tracker = CoverageTracker()
        result = "No results found"
        
        newly_covered = tracker.auto_mark_from_result(
            tool_name="list_strings",
            tool_params={"filter": "service"},
            result=result
        )
        
        # "service" in params should match service_management
        self.assertIn("service_management", newly_covered)
    
    def test_auto_mark_multiple_areas_at_once(self):
        """Multiple areas can be covered by a single result."""
        tracker = CoverageTracker()
        result = 'CreateProcessW, LoadLibraryExW, AdjustTokenPrivileges, RegOpenKeyExW'
        
        newly_covered = tracker.auto_mark_from_result(
            tool_name="list_imports",
            tool_params={},
            result=result
        )
        
        # Should cover process_creation, dll_loading, privilege_escalation, registry_persistence
        self.assertGreaterEqual(len(newly_covered), 4)
    
    def test_already_covered_not_re_reported(self):
        """Already-covered areas are not reported again."""
        tracker = CoverageTracker()
        result = "CreateProcessW found"
        
        covered1 = tracker.auto_mark_from_result("list_imports", {}, result)
        covered2 = tracker.auto_mark_from_result("list_imports", {}, result)
        
        self.assertIn("process_creation", covered1)
        self.assertNotIn("process_creation", covered2)
    
    def test_no_match_returns_empty(self):
        """No matches returns empty list."""
        tracker = CoverageTracker()
        result = "Nothing interesting here at all"
        
        newly_covered = tracker.auto_mark_from_result("some_tool", {}, result)
        self.assertEqual(len(newly_covered), 0)


class TestCoverageTrackerQueries(unittest.TestCase):
    """Tests for querying coverage state."""
    
    def test_get_uncovered_initially_all(self):
        """All areas are uncovered initially."""
        tracker = CoverageTracker()
        uncovered = tracker.get_uncovered()
        self.assertEqual(len(uncovered), 8)
    
    def test_get_uncovered_after_marking(self):
        """Uncovered count decreases after marking."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "tool")
        uncovered = tracker.get_uncovered()
        self.assertEqual(len(uncovered), 7)
    
    def test_get_covered(self):
        """Covered list returns marked areas."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "tool")
        tracker.mark_covered("network_comms", "tool")
        covered = tracker.get_covered()
        self.assertEqual(len(covered), 2)
    
    def test_coverage_ratio_zero(self):
        """Coverage ratio is 0 when nothing covered."""
        tracker = CoverageTracker()
        self.assertAlmostEqual(tracker.coverage_ratio(), 0.0)
    
    def test_coverage_ratio_full(self):
        """Coverage ratio is 1.0 when all covered."""
        tracker = CoverageTracker()
        for name in list(tracker.areas.keys()):
            tracker.mark_covered(name, "tool")
        self.assertAlmostEqual(tracker.coverage_ratio(), 1.0)
    
    def test_coverage_ratio_partial(self):
        """Coverage ratio reflects partial coverage."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "tool")
        tracker.mark_covered("network_comms", "tool")
        self.assertAlmostEqual(tracker.coverage_ratio(), 2 / 8)
    
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
    
    def test_format_shows_uncovered_areas(self):
        """Format shows uncovered areas with search hints."""
        tracker = CoverageTracker()
        output = tracker.format_for_prompt()
        self.assertIn("❌ Not Yet Investigated", output)
        self.assertIn("service_management", output)
        self.assertIn("Search for:", output)
    
    def test_format_shows_covered_areas(self):
        """Format shows covered areas after marking."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "list_imports", "Found APIs")
        output = tracker.format_for_prompt()
        self.assertIn("✅ Covered", output)
        self.assertIn("service_management", output)
        self.assertIn("Found APIs", output)
    
    def test_format_shows_progress(self):
        """Format shows progress count."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "tool")
        output = tracker.format_for_prompt()
        self.assertIn("1/8", output)
    
    def test_format_uncovered_has_api_hints(self):
        """Uncovered areas include API name hints."""
        tracker = CoverageTracker()
        output = tracker.format_for_prompt()
        self.assertIn("CreateServiceW", output)


class TestCoverageTrackerReset(unittest.TestCase):
    """Tests for reset functionality."""
    
    def test_reset_clears_all_coverage(self):
        """Reset marks all areas as uncovered."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "tool", "Found")
        tracker.mark_covered("network_comms", "tool", "Found")
        
        tracker.reset()
        
        self.assertEqual(len(tracker.get_covered()), 0)
        self.assertEqual(len(tracker.get_uncovered()), 8)
        self.assertAlmostEqual(tracker.coverage_ratio(), 0.0)
    
    def test_reset_clears_metadata(self):
        """Reset clears covered_by, result_summary, and hits."""
        tracker = CoverageTracker()
        tracker.mark_covered("service_management", "list_imports", "Found OpenServiceW")
        tracker.areas["service_management"].hits = 5
        
        tracker.reset()
        
        area = tracker.areas["service_management"]
        self.assertFalse(area.covered)
        self.assertIsNone(area.covered_by)
        self.assertIsNone(area.result_summary)
        self.assertEqual(area.hits, 0)


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
    
    def test_privilege_escalation_has_key_apis(self):
        """Privilege escalation area includes token manipulation APIs."""
        apis = DEFAULT_CHECKLIST["privilege_escalation"]["apis"]
        self.assertIn("AdjustTokenPrivileges", apis)
        self.assertIn("OpenProcessToken", apis)


if __name__ == "__main__":
    unittest.main()
