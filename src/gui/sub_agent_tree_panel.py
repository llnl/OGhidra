class SubAgentTreePanel:
    """Live sidebar panel showing orchestrator/worker hierarchy as a tree.

    Polls a thread-safe SubAgentRegistry and renders the state into a
    ttk.Treeview.  Supports collapsing to save sidebar space.
    """

    POLL_ACTIVE_MS = 200     # Fast refresh while orchestrator is running
    POLL_IDLE_MS = 2000      # Slow refresh when idle

    # Unicode status icons
    _ICONS = {
        "complete": "\u2713",    # ✓
        "running":  "\u27F3",    # ⟳
        "error":    "\u2717",    # ✗
        "pending":  "\u25CB",    # ○
    }

    def __init__(self, parent, registry):
        from src.agents.base import SubAgentRegistry  # noqa: F811
        self.registry: SubAgentRegistry = registry
        self._collapsed = False

        colors = _theme_colors

        # Outer frame
        self.frame = ttk.LabelFrame(parent, text="Sub-Agents", padding=8)

        # Header row: collapse toggle + summary
        header = ttk.Frame(self.frame)
        header.pack(fill='x')

        self.toggle_btn = ttk.Button(
            header, text="\u25BC", width=3,
            command=self._toggle_collapse,
        )
        self.toggle_btn.pack(side='left')

        self.summary_label = ttk.Label(
            header, text="Idle", font=('Segoe UI', 9),
        )
        self.summary_label.pack(side='left', padx=(6, 0))

        # Collapsible content
        self.content_frame = ttk.Frame(self.frame)
        self.content_frame.pack(fill='both', expand=True, pady=(4, 0))

        # Treeview (tree-only, no column headers)
        tree_container = ttk.Frame(self.content_frame)
        tree_container.pack(fill='both', expand=True)
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            tree_container, show='tree', height=12, selectmode='none',
        )
        scrollbar = ttk.Scrollbar(
            tree_container, orient='vertical', command=self.tree.yview,
        )
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        scrollbar.grid(row=0, column=1, sticky='ns')

        # Start polling
        self._poll()

    def get_widget(self):
        """Return the frame widget."""
        return self.frame

    # ── Collapse toggle ──

    def _toggle_collapse(self):
        self._collapsed = not self._collapsed
        if self._collapsed:
            self.content_frame.pack_forget()
            self.toggle_btn.config(text="\u25B6")
        else:
            self.content_frame.pack(fill='both', expand=True, pady=(4, 0))
            self.toggle_btn.config(text="\u25BC")

    # ── Polling loop ──

    def _poll(self):
        try:
            if self.registry.is_dirty:
                state = self.registry.get_state()
                self._render(state)
        except Exception as e:
            logger.error(f"SubAgentTreePanel poll error: {e}")

        interval = (
            self.POLL_ACTIVE_MS if self.registry.is_active
            else self.POLL_IDLE_MS
        )
        self.frame.after(interval, self._poll)

    # ── Rendering ──

    def _render(self, state):
        """Rebuild treeview from an OrchestratorState snapshot."""
        # Clear
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not state.active and not state.workers:
            self.summary_label.config(text="Idle")
            return

        area_pct = int(state.coverage_ratio * 100)

        # Build function coverage string
        func_cov_str = self._format_func_coverage(
            state.functions_analyzed, state.functions_total
        )

        # Summary label — show area coverage clearly
        if state.active:
            self.summary_label.config(
                text=f"Cycle {state.cycle}/{state.max_cycles}, "
                     f"areas {area_pct}%",
            )
        else:
            self.summary_label.config(
                text=f"Done ({state.exit_reason}, "
                     f"areas {area_pct}%)",
            )

        # Root: Orchestrator — label the metric clearly as "area coverage"
        orch_text = (
            f"Orchestrator [cycle {state.cycle}/{state.max_cycles}, "
            f"area coverage {area_pct}%]"
        )
        orch_item = self.tree.insert("", "end", text=orch_text, open=True)

        # Function coverage row (child of orchestrator) — separate metric
        if func_cov_str:
            self.tree.insert(
                orch_item, "end",
                text=f"\U0001F4CA Func analysis: {func_cov_str}",
            )

        # Children: Workers
        for w in state.workers:
            icon = self._ICONS.get(w.status, "?")
            goal_short = w.goal[:50] + ("..." if len(w.goal) > 50 else "")

            # Build recipe prefix (e.g. "[trace_import_callers] ")
            prefix = f"[{w.recipe}] " if w.recipe else ""

            if w.status == "running":
                tool_info = f"{w.real_tool_count} tools" if w.real_tool_count else ""
                if w.recipe and w.phase:
                    # Recipe worker: show phase name instead of step counter
                    detail = w.phase
                else:
                    # LLM worker: show step counter
                    detail = f"step {w.current_step}/{w.soft_limit}"
                if tool_info:
                    detail += f", {tool_info}"
                detail += "..."
            elif w.status in ("complete", "error"):
                detail = f"{w.exit_reason}, {w.real_tool_count} tools"
            else:
                detail = "pending"

            text = f'Worker #{w.worker_number}: {prefix}"{goal_short}" {icon} ({detail})'
            self.tree.insert(orch_item, "end", text=text)

    @staticmethod
    def _format_func_coverage(analyzed: int, total: int) -> str:
        """Format function coverage for display in the tree panel.

        Returns an empty string when no data is available yet.
        """
        if analyzed == 0 and total == 0:
            return ""
        if total > 0:
            pct = int(analyzed / total * 100)
            return f"{analyzed}/{total} ({pct}%)"
        return f"{analyzed} analyzed"
