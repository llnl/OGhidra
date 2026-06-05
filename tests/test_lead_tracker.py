import unittest
from src.lead_tracker import LeadTracker


class TestLeadTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = LeadTracker()

    def test_add_lead(self):
        """Test adding leads with different priorities."""
        self.assertTrue(self.tracker.add_lead("Lead A", "HIGH"))
        self.assertTrue(self.tracker.add_lead("Lead B", "MEDIUM"))
        self.assertTrue(self.tracker.add_lead("Lead C", "LOW"))

        # Test default priority
        self.assertTrue(self.tracker.add_lead("Lead D", "INVALID_PRIO"))
        # After sorting (HIGH, MEDIUM, MEDIUM, LOW), Lead D (MEDIUM) should be present
        lead_d = next(lead for lead in self.tracker.leads if lead.description == "Lead D")
        self.assertEqual(lead_d.priority, "MEDIUM")

    def test_duplicate_leads(self):
        """Test that duplicate leads are rejected."""
        self.tracker.add_lead("Same", "HIGH", "0x123")
        self.assertFalse(self.tracker.add_lead("Same", "HIGH", "0x123"))

        # Different address should be accepted
        self.assertTrue(self.tracker.add_lead("Same", "HIGH", "0x456"))

    def test_sorting(self):
        """Test that leads are sorted by priority (HIGH > MEDIUM > LOW)."""
        self.tracker.add_lead("Medium lead", "MEDIUM")
        self.tracker.add_lead("Low lead", "LOW")
        self.tracker.add_lead("High lead", "HIGH")

        self.assertEqual(self.tracker.leads[0].priority, "HIGH")
        self.assertEqual(self.tracker.leads[1].priority, "MEDIUM")
        self.assertEqual(self.tracker.leads[2].priority, "LOW")

    def test_parse_analysis_dump(self):
        """Test parsing leads from analysis dump content."""
        dump_content = """
        ## Investigation Leads
        - [HIGH] 0x004a0e20: Call to AdjustTokenPrivileges from FUN_004a0e28.
        - [MEDIUM] 0x0040e3d0: CreateProcessW called from FUN_004a143c.
        """
        count = self.tracker.parse_analysis_dump(dump_content)
        self.assertEqual(count, 2)

        high_lead = self.tracker.leads[0]
        self.assertEqual(high_lead.priority, "HIGH")
        self.assertEqual(high_lead.source_address, "0x004a0e20")
        self.assertIn("Call to AdjustTokenPrivileges", high_lead.description)

    def test_format_for_prompt(self):
        """Test formatting leads for LLM prompt."""
        self.tracker.add_lead("Critical issue", "HIGH")
        formatted = self.tracker.format_for_prompt()

        self.assertIn("🔴 **HIGH**: Critical issue", formatted)
        self.assertIn("You MUST address all HIGH priority leads", formatted)

    def test_reset(self):
        """Test resetting the tracker."""
        self.tracker.add_lead("To be deleted", "HIGH")
        self.assertEqual(len(self.tracker.leads), 1)
        self.tracker.reset()
        self.assertEqual(len(self.tracker.leads), 0)
        self.assertEqual(len(self.tracker.seen_leads), 0)


if __name__ == "__main__":
    unittest.main()
