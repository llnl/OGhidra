from ttkbootstrap import Style


class ThemeColors:
    """Theme-aware colors for raw tk widgets (Canvas, Text, Listbox, etc.)."""

    def __init__(self, style: Style):
        """Initialize with a ttkbootstrap style object."""
        colors = style.colors

        # Main backgrounds
        self.bg = colors.bg  # Main window background
        self.inputbg = colors.inputbg  # Input field background
        self.selectbg = colors.selectbg  # Selection background

        # Foregrounds
        self.fg = colors.fg  # Main text color
        self.inputfg = colors.inputfg  # Input text color
        self.selectfg = colors.selectfg  # Selected text color

        # Accent colors
        self.primary = colors.primary  # Primary accent (blue)
        self.secondary = colors.secondary  # Secondary accent
        self.success = colors.success  # Success/green
        self.info = colors.info  # Info/cyan
        self.warning = colors.warning  # Warning/orange
        self.danger = colors.danger  # Error/red

        # Border
        self.border = colors.border

        # Computed colors for specific use cases
        self.canvas_bg = colors.bg  # Canvas background
        self.text_font = ("Consolas", 11)  # Softer monospace font
        self.ui_font = ("Segoe UI", 10)  # UI font
        self.ui_font = ("Segoe UI", 10)  # UI font
