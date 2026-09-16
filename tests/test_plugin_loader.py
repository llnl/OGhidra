"""Offline tests for explicit plugin loading, isolation, ordering and resources."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.plugins import PluginError, PluginManager, PluginResources, ResourceError
from src.plugins.loader import compatible_api
from src.plugins.resources import contained_path, skill_metadata
from src.workflow import RunContext, WorkContext, WorkflowRuntime, WorkItem, WorkPlan

SKILL = "---\nname: review\ndescription: Review function evidence.\n---\nCheck supporting addresses."


class PluginLoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = WorkflowRuntime()
        self.runtime.register_operation("echo", lambda item, ctx: item.input)
        self.manager = PluginManager(self.runtime)
        quiet = patch("src.plugins.loader._logger.warning")
        quiet.start()
        self.addCleanup(quiet.stop)

    def plugin(self, name="example", code=None, files=None, **fields):
        root = self.root / name
        root.mkdir(parents=True, exist_ok=True)
        data = {"id": name, "version": "0.1.0", "host_api": ">=1,<2", "contributions": []}
        if code is not None:
            data["entrypoint"] = "plugin:activate"
            (root / "plugin.py").write_text(code, encoding="utf-8")
        data.update(fields)
        manifest = root / "plugin.toml"
        manifest.write_text("\n".join(f"{key} = {json.dumps(value)}" for key, value in data.items()), encoding="utf-8")
        for path, value in (files or {}).items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(value, bytes):
                target.write_bytes(value)
            else:
                target.write_text(value, encoding="utf-8")
        return manifest

    def load_one(self, manifest, config=None):
        settings = {} if config is None else {manifest.parent.name: config}
        return self.manager.load([manifest], settings=settings)[0]

    def test_no_plugins_and_bad_load_arguments(self):
        self.assertEqual(self.manager.load([]), [])
        self.assertEqual(self.manager.inventory(), [])
        for paths, settings in [("plugin.toml", {}), (Path("plugin.toml"), {}), ([], [])]:
            with self.assertRaises(PluginError):
                self.manager.load(paths, settings)

    def test_version_constraints(self):
        for value in [">=1,<2", "==1.0", "<=1.0.0,!=2", ">0.9"]:
            self.assertTrue(compatible_api(value))
        for value in [">1", "<1", "==2", "!=1"]:
            self.assertFalse(compatible_api(value))
        for value in [None, "", "1", "~=1", ">=1,", ">=1.0.0.0", ">=1-beta"]:
            with self.assertRaises(PluginError):
                compatible_api(value)

    def test_manifest_validation(self):
        bad = [
            {"id": "../oops"}, {"id": 12}, {"version": ""}, {"version": 1},
            {"host_api": ">=2"}, {"entrypoint": "../plugin:activate"}, {"entrypoint": 1},
            {"contributions": "context.collect"}, {"contributions": [1]},
            {"contributions": ["context.collect", "context.collect"]},
            {"contributions": ["workflow.plna"]}, {"contributions": ["event:workflow.plan"]},
            {"dependencies": ["../bad"]}, {"dependencies": ["example"]},
            {"resources": ["notes.md"]},
        ]
        for fields in bad:
            with self.subTest(fields=fields):
                status = self.load_one(self.plugin(**fields))
                self.assertEqual(status.status, "error")
        for path in [self.root / "missing" / "plugin.toml", self.root / "wrong.toml"]:
            self.assertEqual(self.load_one(path).status, "error")
        manifest = self.plugin()
        manifest.write_bytes(b"bad TOML = [")
        self.assertEqual(self.load_one(manifest).status, "error")
        manifest.write_bytes(b"#" * (65536 + 1))
        self.assertIn("64 KiB", self.load_one(manifest).error)

    def test_disabled_plugin_never_imports_or_reads_resources(self):
        manifest = self.plugin(
            code="raise RuntimeError('MUST NOT IMPORT')",
            contributions=["context.collect"], resources=["missing.txt"],
        )
        status = self.load_one(manifest, {"enabled": False})
        self.assertEqual(status.status, "disabled")
        self.assertEqual(status.resources, [])

    def test_invalid_settings_are_reported(self):
        for config in [[], {"enabled": "yes"}, {"active_skills": "review"},
                       {"active_skills": [1]}, {"include_resources": "yes"}]:
            with self.subTest(config=config):
                self.assertEqual(self.load_one(self.plugin(), config).status, "error")

    def test_isolated_relative_imports_and_config(self):
        original_path = list(sys.path)
        for name, value in [("alpha", 1), ("beta", 2)]:
            manifest = self.plugin(
                name,
                code="from .helper import VALUE\ndef activate(api):\n"
                     "    api.register_operation(api.plugin_id, lambda item, ctx: VALUE + api.config['extra'])\n",
                files={"helper.py": f"VALUE = {value}\n"}, contributions=["operations"],
            )
            self.assertEqual(self.load_one(manifest, {"extra": 10}).status, "active")
        result = self.runtime.run(WorkPlan([WorkItem("a", "alpha"), WorkItem("b", "beta")]), RunContext())
        self.assertEqual([result["a"].value, result["b"].value], [11, 12])
        self.assertEqual(sys.path, original_path)

    def test_package_entrypoint(self):
        manifest = self.plugin(
            files={"ext/__init__.py": "def activate(api):\n    pass\n"},
            entrypoint="ext:activate",
        )
        self.assertEqual(self.load_one(manifest).status, "active")

    def test_failed_activation_stages_nothing_and_removes_modules(self):
        manifest = self.plugin(
            code="from . import helper\ndef activate(api):\n"
                 "    api.register_operation('leaked', lambda item, ctx: None)\n"
                 "    raise RuntimeError('activation failed')\n",
            files={"helper.py": "VALUE = 1"}, contributions=["operations"],
        )
        before = set(sys.modules)
        status = self.load_one(manifest)
        self.assertIn("activation failed", status.error)
        self.assertFalse(any(name.startswith("_oghidra_plugin_") for name in set(sys.modules) - before))
        with self.assertRaisesRegex(ValueError, "Unknown operation"):
            self.runtime.validate_plan(WorkPlan([WorkItem("x", "leaked")]))

    def test_commit_failure_rolls_back_operations_and_hooks(self):
        manifest = self.plugin(
            code="def activate(api):\n"
                 "    api.add_hook('workflow.plan', lambda plan, ctx: None)\n"
                 "    api.register_operation('new', lambda item, ctx: None)\n"
                 "    api.register_operation('echo', lambda item, ctx: None)\n",
            contributions=["operations", "workflow.plan"],
        )
        self.assertIn("already registered", self.load_one(manifest).error)
        run = RunContext()
        result = self.runtime.run(WorkPlan([WorkItem("x", "echo", {"a": 1})]), run)
        self.assertEqual(result["x"].value, {"a": 1})
        self.assertNotIn("hook_errors", run.state)
        with self.assertRaisesRegex(ValueError, "Unknown operation"):
            self.runtime.validate_plan(WorkPlan([WorkItem("x", "new")]))

    def test_entrypoint_missing_noncallable_and_async_errors(self):
        for code, entrypoint in [
            (None, "missing:activate"),
            ("activate = 2", "plugin:activate"),
            ("async def activate(api):\n    pass", "plugin:activate"),
        ]:
            with self.subTest(code=code):
                manifest = self.plugin(code=code, entrypoint=entrypoint)
                self.assertEqual(self.load_one(manifest).status, "error")

    def test_registration_guards(self):
        statements = [
            ("api.add_hook('workflow.plna', lambda *_: None)", ["workflow.plan"]),
            ("api.add_hook('workflow.plan', None)", ["workflow.plan"]),
            ("api.add_hook('workflow.plan', lambda *_: None, True)", ["workflow.plan"]),
            ("api.add_hook('workflow.plan', lambda *_: None)", []),
            ("api.register_operation('', lambda *_: None)", ["operations"]),
            ("api.register_operation('x', lambda *_: None)", []),
            ("api.subscribe('workflow.plan', lambda *_: None)", ["observer"]),
            ("api.subscribe('bad event', lambda *_: None)", ["observer"]),
            ("api.subscribe('custom.done', lambda *_: None)", []),
        ]
        for statement, declarations in statements:
            with self.subTest(statement=statement):
                manifest = self.plugin(code=f"def activate(api):\n    {statement}\n", contributions=declarations)
                self.assertEqual(self.load_one(manifest).status, "error")

    def test_registration_closed_after_activation(self):
        manifest = self.plugin()
        self.assertEqual(self.load_one(manifest).status, "active")
        api = self.manager._active["example"]
        with self.assertRaisesRegex(PluginError, "only allowed during"):
            api.register_operation("late", lambda *_: None)

    def test_named_custom_and_wildcard_events(self):
        manifest = self.plugin(
            code="def activate(api):\n"
                 "    def observe(event, run):\n"
                 "        run.state.setdefault('seen', []).append(event.name)\n"
                 "    api.subscribe('analysis.completed', observe)\n"
                 "    api.subscribe('custom.done', observe)\n",
            contributions=["analysis.completed", "event:custom.done"],
        )
        self.assertEqual(self.load_one(manifest).status, "active")
        other = self.plugin(
            "wild",
            code="def activate(api):\n"
                 "    api.add_hook('observer', lambda event, run: run.state.setdefault('all', []).append(event.name))\n"
                 "    api.subscribe('program.changed', lambda event, run: run.state.update(changed=True))\n",
            contributions=["observer"],
        )
        self.assertEqual(self.load_one(other).status, "active")
        run = RunContext()
        for event in ["analysis.completed", "custom.done", "program.changed"]:
            self.runtime.emit(event, {}, run)
        self.assertEqual(run.state["seen"], ["analysis.completed", "custom.done"])
        self.assertEqual(run.state["all"], ["analysis.completed", "custom.done", "program.changed"])
        self.assertTrue(run.state["changed"])

    def test_dependencies_and_ordering_are_deterministic(self):
        code = "def activate(api):\n    api.add_hook('observer', lambda event, run: run.state.setdefault('order', []).append(api.plugin_id))\n"
        manifests = [
            self.plugin("a", code=code, contributions=["observer"], after=["b"]),
            self.plugin("b", code=code, contributions=["observer"], dependencies=["c"]),
            self.plugin("c", code=code, contributions=["observer"], before=["a"]),
            self.plugin("d", code=code, contributions=["observer"], after=["absent"]),
        ]
        statuses = self.manager.load(manifests)
        self.assertTrue(all(status.status == "active" for status in statuses))
        run = RunContext()
        self.runtime.emit("test", {}, run)
        self.assertEqual(run.state["order"], ["c", "d", "b", "a"])

    def test_cycle_missing_and_failed_dependencies(self):
        a = self.plugin("a", dependencies=["b"])
        b = self.plugin("b", after=["a"])
        c = self.plugin("c", dependencies=["missing"])
        statuses = self.manager.load([a, b, c])
        self.assertTrue(all(status.status == "error" for status in statuses))
        self.assertIn("cycle", statuses[0].error)
        self.assertIn("not active", statuses[2].error)
        d = self.plugin("d", code="raise RuntimeError('broken')")
        e = self.plugin("e", dependencies=["d"])
        states = self.manager.load([e, d])
        self.assertIn("not active", states[0].error)
        self.assertIn("broken", states[1].error)

    def test_existing_dependency_and_duplicate_ids(self):
        manifest = self.plugin("a")
        self.assertEqual(self.load_one(manifest).status, "active")
        self.assertEqual(self.load_one(self.plugin("b", dependencies=["a"])).status, "active")
        self.assertIn("Duplicate", self.load_one(manifest).error)
        first = self.plugin("same")
        second = self.plugin("other", id="same")
        states = self.manager.load([first, second])
        self.assertTrue(all(status.status == "error" for status in states))
        self.assertNotIn("same", self.manager._active)

    def test_resource_only_and_explicit_skill_selection(self):
        manifest = self.plugin(
            files={"docs/note.txt": "Observed evidence", "skills/review/SKILL.md": SKILL,
                   "docs/ignored.py": "raise RuntimeError()"},
            contributions=["context.collect"], resources=["docs", "skills"],
        )
        self.assertEqual(self.load_one(manifest).status, "active")
        item = WorkItem("a", "echo")
        run = RunContext()
        blocks = self.runtime._collect_context(item, WorkContext(run, item))
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].kind, "evidence")
        self.assertIn("docs/note.txt", blocks[0].source)
        inventory = self.manager.inventory()
        self.assertEqual(len(inventory[0]["resources"]), 2)
        inventory[0]["resources"].clear()
        self.assertEqual(len(self.manager.inventory()[0]["resources"]), 2)

        runtime = WorkflowRuntime()
        manager = PluginManager(runtime)
        states = manager.load([manifest], {"example": {"active_skills": ["review"], "include_resources": False}})
        self.assertEqual(states[0].active_skills, ["review"])
        blocks = runtime._collect_context(item, WorkContext(run, item))
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].kind, "instruction")
        self.assertIn("Check supporting", blocks[0].text)

    def test_unknown_skill_rejects_activation(self):
        manifest = self.plugin(files={"SKILL.md": SKILL}, resources=["SKILL.md"], contributions=["context.collect"])
        self.assertIn("Unknown active_skills", self.load_one(manifest, {"active_skills": ["missing"]}).error)

    def test_async_callbacks_and_system_exit_are_isolated(self):
        manifest = self.plugin(
            code="async def handler(item, ctx):\n    return 1\ndef activate(api):\n"
                 "    api.register_operation('async', handler)\n",
            contributions=["operations"],
        )
        self.assertIn("synchronous", self.load_one(manifest).error)
        manifest = self.plugin(code="raise SystemExit('plugin exit')")
        self.assertIn("SystemExit", self.load_one(manifest).error)

    def test_custom_awaitable_activation_is_rejected(self):
        manifest = self.plugin(
            code="class Wait:\n    def __await__(self):\n        yield None\n"
                 "def activate(api):\n    return Wait()\n",
        )
        self.assertIn("synchronous", self.load_one(manifest).error)

    def test_optional_before_absent_and_invalid_host_constant(self):
        self.assertEqual(self.load_one(self.plugin(before=["absent"])).status, "active")
        with patch("src.plugins.loader.API_VERSION", "invalid"), self.assertRaises(PluginError):
            compatible_api(">=1")


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        return path

    def test_path_rejections(self):
        for path in ["../outside.txt", "/absolute", "C:/absolute", "a\\b.txt", "", 1, "a/../../b"]:
            with self.subTest(path=path), self.assertRaises(ResourceError):
                contained_path(self.root, path)

    def test_resource_format_missing_size_and_encoding_errors(self):
        self.write("bad.py", "print('no')")
        self.write("bad.txt", b"\xff")
        self.write("large.txt", "x" * 65537)
        for path in ["bad.py", "bad.txt", "large.txt", "missing.md"]:
            with self.subTest(path=path), self.assertRaises(ResourceError):
                PluginResources(self.root, [path])

    def test_resource_limits(self):
        self.write("docs/a.txt", "abc")
        self.write("docs/b.txt", "def")
        with patch("src.plugins.resources.MAX_RESOURCES", 1), self.assertRaisesRegex(ResourceError, "text resources"):
            PluginResources(self.root, ["docs"])
        with patch("src.plugins.resources.MAX_TOTAL_BYTES", 5), self.assertRaisesRegex(ResourceError, "total bytes"):
            PluginResources(self.root, ["docs"])
        with patch("src.plugins.resources.MAX_DIRECTORY_ENTRIES", 1), self.assertRaisesRegex(ResourceError, "too many"):
            PluginResources(self.root, ["docs"])

    def test_symlink_escape_is_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "x.txt").write_text("outside")
        plugin_root = self.root / "plugin"
        plugin_root.mkdir()
        try:
            (plugin_root / "escape").symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"Symlinks unavailable: {error}")
        with self.assertRaisesRegex(ResourceError, "escapes"):
            PluginResources(plugin_root, ["escape"])
        with self.assertRaisesRegex(ResourceError, "escapes"):
            PluginResources(plugin_root, ["."])

    def test_metadata_parser(self):
        parsed = skill_metadata("---\n# comment\n\nname: 'review'\ndescription: \"A useful review.\"\n---\nbody")
        self.assertEqual(parsed["name"], "review")
        for text in [
            "body", "---\nname: review", "---\nname: review\n---",
            "---\nname: review\nname: duplicate\ndescription: value\n---",
            "---\nnot a field\n---", "---\nname: 'unterminated\n---",
            "---\nname: review\ndescription: |\n---",
        ]:
            with self.subTest(text=text), self.assertRaises(ResourceError):
                skill_metadata(text)

    def test_resource_snapshot_selectors_and_unlisted_reads(self):
        path = self.write("skills/review/SKILL.md", SKILL)
        self.write("note.md", "first")
        resources = PluginResources(self.root, ["skills", "note.md"])
        path.write_text("changed")
        self.assertEqual(resources.read("skills/review/SKILL.md"), SKILL)
        for selector in ["review", "skills/review", "skills/review/SKILL.md"]:
            chosen = resources.selected([selector], include_resources=False)
            self.assertEqual([resource.name for resource in chosen], ["review"])
        with self.assertRaisesRegex(ResourceError, "not declared"):
            resources.read("not-declared.txt")
        self.assertEqual(len(resources.selected([], include_resources=False)), 0)
        path.write_text(SKILL, encoding="utf-8")
        self.write("skills/second/SKILL.md", SKILL)
        with self.assertRaisesRegex(ResourceError, "Duplicate skill"):
            PluginResources(self.root, ["skills"])

    def test_resolved_escape_and_unreadable_directory(self):
        original = Path.resolve
        target = self.root / "escape.txt"
        outside = self.root.parent / "outside.txt"

        def resolve(path, *args, **kwargs):
            return outside if path == target else original(path, *args, **kwargs)

        with patch.object(Path, "resolve", resolve), self.assertRaisesRegex(ResourceError, "escapes"):
            contained_path(self.root, "escape.txt")

        def unreadable(path, **kwargs):
            kwargs["onerror"](PermissionError("denied"))
            return iter(())

        with patch("src.plugins.resources.os.walk", unreadable), self.assertRaisesRegex(ResourceError, "Cannot read"):
            PluginResources(self.root, ["."])

    def test_nonregular_resource_rejected_at_catalog_and_read(self):
        self.write("special.txt", "value")
        with patch.object(Path, "is_file", return_value=False), self.assertRaisesRegex(ResourceError, "not a regular"):
            PluginResources(self.root, ["special.txt"])
        with patch.object(Path, "is_file", side_effect=[True, False]), self.assertRaisesRegex(ResourceError, "not a regular"):
            PluginResources(self.root, ["special.txt"])


if __name__ == "__main__":
    unittest.main()

