import tkinter as tk

from .theme_colors import ThemeColors


# Enhanced WorkflowDiagram class with RAG vector creation stage
class WorkflowDiagram:
    """Visual representation of the agentic workflow stages."""

    def __init__(self, parent, theme_colors: ThemeColors, width=400, height=100):
        # Get theme colors for dark styling
        self._theme_colors = theme_colors
        if self._theme_colors:
            canvas_bg = self._theme_colors.bg
            self.idle_color = "#4a4a4a"  # Dark gray for idle
            self.text_idle_color = "#a0a0a0"  # Light gray text
            self.stage_colors = {
                "Planning": self._theme_colors.info,  # Cyan/blue
                "Execution": self._theme_colors.warning,  # Orange
                "Analysis": self._theme_colors.success,  # Green
                "Review": self._theme_colors.secondary,  # Purple-ish
                "idle": self.idle_color,
            }
        else:
            canvas_bg = "#303030"
            self.idle_color = "#4a4a4a"
            self.text_idle_color = "#a0a0a0"
            self.stage_colors = {
                "Planning": "#3498db",
                "Execution": "#f39c12",
                "Analysis": "#2ecc71",
                "Review": "#9b59b6",
                "idle": self.idle_color,
            }

        self.canvas = tk.Canvas(
            parent,
            width=width,
            height=height,
            bg=canvas_bg,
            relief="flat",
            bd=0,
            highlightthickness=0,
        )
        self.width = width
        self.height = height
        self.current_stage = None
        self.stages = ["Planning", "Execution", "Analysis", "Review"]

        # RAG vector progress tracking (for status display only)
        self.rag_progress = 0
        self.rag_total = 0
        self.rag_active = False
        self.rag_status_text = ""

        self._draw_workflow()

    def _draw_workflow(self):
        """Draw the workflow diagram."""
        self.canvas.after(0, lambda: self.canvas.delete("all"))

        # Calculate positions
        stage_width = (self.width - 40) // len(self.stages)
        y_center = self.height // 2

        for i, stage in enumerate(self.stages):
            x_start = 20 + i * stage_width
            x_center = x_start + stage_width // 2

            # Determine color (dark theme aware)
            if self.current_stage == stage.lower().replace(" ", "_"):
                color = self.stage_colors[stage]
                text_color = "white"
                outline_color = "#ffffff"
            else:
                color = self.stage_colors["idle"]
                text_color = self.text_idle_color
                outline_color = "#5a5a5a"

                # Draw stage box with rounded appearance (using softer outline)
                self.canvas.after(
                    0,
                    lambda: self.canvas.create_rectangle(
                        x_start,
                        y_center - 15,
                        x_start + stage_width - 10,
                        y_center + 15,
                        fill=color,
                        outline=outline_color,
                        width=1,
                    ),
                )

                # Draw stage text
                self.canvas.after(
                    0,
                    lambda: self.canvas.create_text(
                        x_center - 5,
                        y_center,
                        text=stage,
                        fill=text_color,
                        font=("Segoe UI", 9, "bold"),
                    ),
                )
            # Draw arrow to next stage (light color for dark theme)
            if i < len(self.stages) - 1:
                arrow_x = x_start + stage_width - 5
                self.canvas.after(
                    0,
                    lambda: self.canvas.create_line(
                        arrow_x,
                        y_center,
                        arrow_x + 10,
                        y_center,
                        arrow=tk.LAST,
                        fill="#6a6a6a",
                        width=2,
                    ),
                )

        # Draw RAG status text below workflow if active
        if self.rag_active and self.rag_status_text:
            self.canvas.after(
                0,
                lambda: self.canvas.create_text(
                    self.width // 2,
                    self.height - 15,
                    text=self.rag_status_text,
                    fill="#e74c3c",
                    font=("Arial", 9, "bold"),
                ),
            )

    def set_current_stage(self, stage: str | None):
        """Set the current active stage."""
        self.current_stage = stage.lower().replace(" ", "_") if stage else None
        if stage != "rag_vectors":
            self.rag_active = False
        self._draw_workflow()

    def set_rag_progress(self, current: int, total: int, active: bool = True):
        """Set RAG vector creation progress."""
        self.rag_progress = current
        self.rag_total = total
        self.rag_active = active
        if active and total > 0:
            percentage = int((current / total) * 100)
            self.rag_status_text = f"Saving RAG vectors: {current}/{total} ({percentage}%)"
        else:
            self.rag_status_text = ""
        self._draw_workflow()

    def complete_rag_stage(self):
        """Mark RAG vector creation as complete."""
        self.rag_active = False
        self.rag_status_text = ""
        self._draw_workflow()

    def get_widget(self):
        """Return the canvas widget."""
        return self.canvas
