"""
Responsive Layout System - Handles terminal size changes and space redistribution.

Provides breakpoint-based layout adaptation for different terminal sizes.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..panels.base import Panel
    from ..modes.manager import ModeManager


class Breakpoint(Enum):
    """
    Terminal size breakpoints.

    Based on common terminal dimensions:
    - TINY: Very small terminals (< 80 cols)
    - SMALL: Standard small (80-119 cols)
    - MEDIUM: Standard medium (120-159 cols)
    - LARGE: Wide terminals (160-199 cols)
    - XLARGE: Very wide terminals (200+ cols)
    """
    TINY = auto()
    SMALL = auto()
    MEDIUM = auto()
    LARGE = auto()
    XLARGE = auto()


@dataclass
class BreakpointThresholds:
    """Width thresholds for breakpoints."""
    tiny: int = 80
    small: int = 120
    medium: int = 160
    large: int = 200


@dataclass
class LayoutConfig:
    """
    Layout configuration for a specific breakpoint.

    Defines how panels are arranged at different terminal sizes.
    """
    breakpoint: Breakpoint
    max_visible_panels: int = 5
    grid_cols: int = 2
    grid_rows: int = 3
    stack_panels: bool = False  # Stack panels vertically when true
    collapse_to_tabs: bool = False  # Use tabs instead of grid
    min_panel_width: int = 30
    min_panel_height: int = 5
    show_stats_bar: bool = True
    compact_titles: bool = False  # Shorter panel titles
    hidden_panels: List[str] = field(default_factory=list)  # Panels to auto-hide


# Default layout configs per breakpoint
DEFAULT_LAYOUTS: Dict[Breakpoint, LayoutConfig] = {
    Breakpoint.TINY: LayoutConfig(
        breakpoint=Breakpoint.TINY,
        max_visible_panels=2,
        grid_cols=1,
        grid_rows=2,
        stack_panels=True,
        compact_titles=True,
        hidden_panels=["flows", "dns", "hosts"],
    ),
    Breakpoint.SMALL: LayoutConfig(
        breakpoint=Breakpoint.SMALL,
        max_visible_panels=3,
        grid_cols=1,
        grid_rows=3,
        stack_panels=True,
        compact_titles=True,
        hidden_panels=["dns", "hosts"],
    ),
    Breakpoint.MEDIUM: LayoutConfig(
        breakpoint=Breakpoint.MEDIUM,
        max_visible_panels=5,
        grid_cols=2,
        grid_rows=3,
        compact_titles=False,
    ),
    Breakpoint.LARGE: LayoutConfig(
        breakpoint=Breakpoint.LARGE,
        max_visible_panels=5,
        grid_cols=2,
        grid_rows=3,
    ),
    Breakpoint.XLARGE: LayoutConfig(
        breakpoint=Breakpoint.XLARGE,
        max_visible_panels=6,
        grid_cols=3,
        grid_rows=2,
    ),
}


class ResponsiveContainer:
    """
    Manages responsive layout based on terminal size.

    The ResponsiveContainer:
    - Monitors terminal size changes
    - Determines the appropriate breakpoint
    - Applies layout configurations
    - Redistributes space among visible panels
    - Triggers layout callbacks on changes
    """

    def __init__(
        self,
        mode_manager: Optional["ModeManager"] = None,
        thresholds: Optional[BreakpointThresholds] = None,
        layouts: Optional[Dict[Breakpoint, LayoutConfig]] = None,
    ):
        """
        Initialize the responsive container.

        Args:
            mode_manager: ModeManager instance for coordinating panel visibility
            thresholds: Custom breakpoint thresholds
            layouts: Custom layout configurations per breakpoint
        """
        self._mode_manager = mode_manager
        self._thresholds = thresholds or BreakpointThresholds()
        self._layouts = layouts or dict(DEFAULT_LAYOUTS)
        self._current_breakpoint = Breakpoint.MEDIUM
        self._current_layout = self._layouts[Breakpoint.MEDIUM]
        self._width = 120
        self._height = 40
        self._callbacks: Dict[str, List[Callable]] = {}
        self._panels: Dict[str, "Panel"] = {}

    @property
    def current_breakpoint(self) -> Breakpoint:
        """Get the current breakpoint."""
        return self._current_breakpoint

    @property
    def current_layout(self) -> LayoutConfig:
        """Get the current layout configuration."""
        return self._current_layout

    @property
    def width(self) -> int:
        """Current container width."""
        return self._width

    @property
    def height(self) -> int:
        """Current container height."""
        return self._height

    def register_panel(self, panel: "Panel") -> None:
        """Register a panel for responsive layout."""
        self._panels[panel.id] = panel

    def set_mode_manager(self, manager: "ModeManager") -> None:
        """Set the mode manager for panel coordination."""
        self._mode_manager = manager

    # ===== SIZE HANDLING =====

    def on_resize(self, width: int, height: int) -> None:
        """
        Handle terminal resize event.

        Args:
            width: New terminal width in columns
            height: New terminal height in rows
        """
        old_width = self._width
        old_height = self._height
        self._width = width
        self._height = height

        # Determine new breakpoint
        new_breakpoint = self._get_breakpoint(width)

        if new_breakpoint != self._current_breakpoint:
            old_breakpoint = self._current_breakpoint
            self._current_breakpoint = new_breakpoint
            self._current_layout = self._layouts[new_breakpoint]
            self._apply_layout()
            self._trigger_callback("breakpoint_changed", old_breakpoint, new_breakpoint)

        # Always redistribute space on resize
        self._redistribute_space()
        self._trigger_callback("resize", old_width, old_height, width, height)

    def _get_breakpoint(self, width: int) -> Breakpoint:
        """Determine breakpoint from width."""
        if width < self._thresholds.tiny:
            return Breakpoint.TINY
        elif width < self._thresholds.small:
            return Breakpoint.SMALL
        elif width < self._thresholds.medium:
            return Breakpoint.MEDIUM
        elif width < self._thresholds.large:
            return Breakpoint.LARGE
        else:
            return Breakpoint.XLARGE

    # ===== LAYOUT APPLICATION =====

    def _apply_layout(self) -> None:
        """Apply the current layout configuration."""
        layout = self._current_layout

        # Auto-hide panels based on layout config
        for panel_id in layout.hidden_panels:
            if panel_id in self._panels:
                self._panels[panel_id].hide()

        # Show non-hidden panels (respect mode manager if present)
        if self._mode_manager:
            visible_panels = self._mode_manager.visible_panels
            for panel_id, panel in self._panels.items():
                if panel_id in visible_panels and panel_id not in layout.hidden_panels:
                    panel.show()
        else:
            for panel_id, panel in self._panels.items():
                if panel_id not in layout.hidden_panels:
                    panel.show()

        # Apply title compaction
        for panel in self._panels.values():
            container = panel.get_container()
            if container:
                if layout.compact_titles:
                    container.add_class("compact-title")
                else:
                    container.remove_class("compact-title")

    def _redistribute_space(self) -> None:
        """Redistribute available space among visible panels."""
        layout = self._current_layout

        # Calculate available space
        stats_height = 1 if layout.show_stats_bar else 0
        header_footer_height = 2
        available_height = self._height - stats_height - header_footer_height

        # Get visible panels
        visible_panels = [
            p for p in self._panels.values()
            if p.is_visible and p.id not in layout.hidden_panels
        ]

        if not visible_panels:
            return

        if layout.stack_panels:
            self._layout_stacked(visible_panels, available_height)
        else:
            self._layout_grid(visible_panels, available_height, layout)

    def _layout_stacked(self, panels: List["Panel"], available_height: int) -> None:
        """Layout panels in a vertical stack."""
        num_panels = len(panels)
        if num_panels == 0:
            return

        # Equal height distribution (minus title bars)
        panel_height = max(
            self._current_layout.min_panel_height,
            available_height // num_panels
        )

        for i, panel in enumerate(panels):
            panel.resize(self._width, panel_height)
            panel.set_position(0, i * panel_height, row=i, col=0)

    def _layout_grid(
        self,
        panels: List["Panel"],
        available_height: int,
        layout: LayoutConfig
    ) -> None:
        """Layout panels in a grid arrangement."""
        rows = layout.grid_rows
        cols = layout.grid_cols

        # Calculate cell dimensions
        cell_width = max(layout.min_panel_width, self._width // cols)
        cell_height = max(layout.min_panel_height, available_height // rows)

        # Assign panels to grid positions based on their priority
        sorted_panels = sorted(panels, key=lambda p: p.config.priority, reverse=True)

        for i, panel in enumerate(sorted_panels[:rows * cols]):
            row = i // cols
            col = i % cols

            panel.resize(cell_width, cell_height)
            panel.set_position(col * cell_width, row * cell_height, row=row, col=col)

    # ===== LAYOUT CUSTOMIZATION =====

    def set_layout(self, breakpoint: Breakpoint, config: LayoutConfig) -> None:
        """
        Set a custom layout configuration for a breakpoint.

        Args:
            breakpoint: Breakpoint to configure
            config: Layout configuration
        """
        self._layouts[breakpoint] = config
        if breakpoint == self._current_breakpoint:
            self._current_layout = config
            self._apply_layout()
            self._redistribute_space()

    def set_thresholds(self, thresholds: BreakpointThresholds) -> None:
        """Set custom breakpoint thresholds."""
        self._thresholds = thresholds
        # Re-evaluate current breakpoint
        self.on_resize(self._width, self._height)

    # ===== CSS GENERATION =====

    def get_responsive_css(self) -> str:
        """
        Generate CSS for responsive layouts.

        Returns:
            CSS string with breakpoint-specific rules
        """
        css_parts = []

        for breakpoint, layout in self._layouts.items():
            css_parts.append(f"""
            /* {breakpoint.name} breakpoint */
            .breakpoint-{breakpoint.name.lower()} {{
                /* Grid: {layout.grid_cols}x{layout.grid_rows} */
            }}

            .breakpoint-{breakpoint.name.lower()} .compact-title {{
                /* Compact title styling */
            }}

            .breakpoint-{breakpoint.name.lower()} #main {{
                /* Main container for this breakpoint */
            }}
            """)

            # Hidden panel rules
            for panel_id in layout.hidden_panels:
                css_parts.append(f"""
                .breakpoint-{breakpoint.name.lower()} #{panel_id}-pane {{
                    display: none;
                }}
                """)

        return "\n".join(css_parts)

    def get_current_css_class(self) -> str:
        """Get the CSS class for the current breakpoint."""
        return f"breakpoint-{self._current_breakpoint.name.lower()}"

    # ===== CALLBACKS =====

    def on(self, event: str, callback: Callable) -> None:
        """
        Register a callback for layout events.

        Events:
            - resize: (old_width, old_height, new_width, new_height)
            - breakpoint_changed: (old_breakpoint, new_breakpoint)
        """
        if event not in self._callbacks:
            self._callbacks[event] = []
        self._callbacks[event].append(callback)

    def _trigger_callback(self, event: str, *args) -> None:
        """Trigger registered callbacks for an event."""
        for callback in self._callbacks.get(event, []):
            try:
                callback(*args)
            except Exception:
                pass

    # ===== UTILITIES =====

    def get_info(self) -> Dict:
        """Get information about the current layout state."""
        return {
            "width": self._width,
            "height": self._height,
            "breakpoint": self._current_breakpoint.name,
            "grid_cols": self._current_layout.grid_cols,
            "grid_rows": self._current_layout.grid_rows,
            "max_visible_panels": self._current_layout.max_visible_panels,
            "stack_panels": self._current_layout.stack_panels,
            "hidden_panels": self._current_layout.hidden_panels,
        }

    def force_refresh(self) -> None:
        """Force a layout refresh."""
        self._apply_layout()
        self._redistribute_space()
