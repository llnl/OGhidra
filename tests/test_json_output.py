"""Tests for --output json in single-query (headless) mode."""

import json
import sys
import unittest
from unittest.mock import MagicMock, patch

import main


def _fake_bridge(result="done", exc=None):
    bridge = MagicMock()

    def process_query(query):
        print("[Bridge] progress noise")
        if exc:
            raise exc
        return result

    bridge.process_query.side_effect = process_query
    return bridge


class TestJsonOutput(unittest.TestCase):
    def _run(self, argv, bridge):
        with (
            patch.object(sys, "argv", ["main.py", *argv]),
            patch.object(main, "Bridge", return_value=bridge),
            patch("sys.stdout") as out,
            patch("sys.stderr"),
        ):
            rc = main.main()
        written = "".join(c.args[0] for c in out.write.call_args_list)
        return rc, written

    def test_format_success(self):
        data = json.loads(main.format_query_json("q", "answer"))
        self.assertEqual(data, {"query": "q", "success": True, "response": "answer"})

    def test_format_error(self):
        data = json.loads(main.format_query_json("q", error=ValueError("boom")))
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], "ValueError: boom")

    def test_stdout_is_only_json(self):
        rc, out = self._run(["--query", "what is this", "--output", "json"], _fake_bridge("hello"))
        self.assertFalse(rc)
        self.assertEqual(json.loads(out)["response"], "hello")

    def test_error_reported_with_nonzero_exit(self):
        rc, out = self._run(["-q", "x", "--output=JSON"], _fake_bridge(exc=RuntimeError("bad")))
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out)["error"], "RuntimeError: bad")

    def test_text_default_unchanged(self):
        rc, out = self._run(["-q", "x"], _fake_bridge("plain"))
        self.assertFalse(rc)
        self.assertIn("plain", out)
        self.assertNotIn('"success"', out)

    def test_json_requires_query(self):
        with (
            patch.object(sys, "argv", ["main.py", "--output", "json"]),
            patch.object(main, "Bridge"),
            patch("sys.stderr"),
            self.assertRaises(SystemExit),
        ):
            main.main()


if __name__ == "__main__":
    unittest.main()
