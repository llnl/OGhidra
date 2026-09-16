# OGhidra workflow plugins

These extensions are separate from Codex plugins. Only explicit configured
`plugin.toml` paths are loaded. No directory scan discovers executable plugins.
Python entrypoints execute trusted code with the host process's permissions.

```toml
id = "example.context"
version = "0.1.0"
host_api = ">=1,<2"
entrypoint = "plugin:activate" # omit for a resource-only plugin
contributions = ["context.collect", "analysis.completed"]
resources = ["docs", "skills/function-review/SKILL.md"]
# dependencies = ["another.plugin"] # must successfully activate first
# after = ["optional.plugin"]       # ordering only, if configured
# before = ["later.plugin"]
```

Host API 1.0 constraints support comma-separated `==`, `!=`, `>=`, `<=`,
`>`, and `<` numeric comparisons with one to three version components.
Prereleases, wildcards, `~=`, and dependency version constraints are unsupported.
Dependencies must be active. Optional ordering edges are ignored when their target
is absent. Cycles and duplicate ids are errors. Ready plugins activate in
alphabetical id order, independently of manifest input order. Hook priority takes
precedence over registration order during execution.

`plugin.py` may use relative imports such as `from .helpers import build_context`.
Each root receives an isolated package namespace; `sys.path` is never modified.
Use synchronous `activate(api)` to register operations and hooks:

```python
from src.workflow import ContextBlock

def activate(api):
    def context(item, ctx):
        return [ContextBlock(
            text="Example reference material", source=f"plugin:{api.plugin_id}",
            priority=10, kind="evidence",
        )]

    def completed(event, run):
        pass # observe committed completion

    api.add_hook("context.collect", context, priority=10)
    api.subscribe("analysis.completed", completed)
```

Hook contributions: `workflow.plan`, `request.prepare`, `context.collect`,
`prompt.transform`, `result.transform`, and `observer`. Declare `operations`
for `api.register_operation(name, handler)`. Declare an event name such as
`analysis.completed`, `program.changed`, `operation.completed`, or
`workflow.completed` for `api.subscribe(name, callback)`. Standard workflow and
operation events accept started/completed/failed/cancelled suffixes, plus
operation.skipped. Custom events must be declared as `event:<name>`. An
`observer` contribution permits named subscriptions or
`api.add_hook("observer", callback)` to observe all events.

Callback contracts are defined in `src.workflow`. Host operation names cannot
be replaced. Staged registrations are discarded if activation fails. Registration
failure rolls back that plugin's commit. Arbitrary import-time/file/network side
effects of trusted code cannot be rolled back. Activation must occur at startup,
without concurrent workflow execution. Reloading requires a fresh runtime.

`api.config` is a copy of plugin settings.
`api.resources.inventory()` lists declared text resources.
`api.resources.read(relative_path)` returns their validated UTF-8 snapshots.
Resources require `context.collect` even for code plugins. Resource paths use
`/`; absolute paths, `..`, Windows drive/stream syntax, and symlink escapes are
rejected. Directories include only `.md` and `.txt`. Limits: 2,048 directory
entries, 128 text files, 64 KiB per file, 1 MiB total, and 64 KiB per manifest.
Resource errors disable the plugin with a diagnostic.

Settings are keyed by manifest id:

```json
{
  "example.context": {
    "enabled": true,
    "include_resources": true,
    "active_skills": ["function-review"]
  }
}
```

`enabled: false` prevents code imports and resource loading.
`include_resources` defaults to true: declared ordinary text is contributed as
evidence. Set false for code-only resource access. Every `SKILL.md` is cataloged
as a skill and is contributed as instructions only when explicitly selected by
`active_skills` (default empty). Select by front matter name, relative SKILL.md
path, or containing directory. Unknown selections are errors. No keyword-based
activation occurs.

Skill front matter must start and end with `---` and provide nonempty `name`
and `description` using single-line `key: value` fields. Simple quoted strings
are supported; YAML structures, block scalars, aliases, tags and multiline values
are unsupported.

```markdown
---
name: function-review
description: Review function behavior with explicit evidence and unresolved checks.
---
Separate observations from hypotheses. Cite the address supporting each finding.
```

Text snapshots remain stable until restart. Instruction and evidence context
blocks retain separate kinds and source labels and share the host's context
budget. `PluginManager.inventory()` reports active, disabled, and failed plugins,
diagnostics, and available resources.

