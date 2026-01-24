"""
Panel Base Class - Abstract interface for all TUI panels.

Each panel represents a distinct data view (credentials, flows, DNS, etc.)
with consistent show/hide/resize semantics and CSS class management.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from textual.widget import Widget
from textual.containers import Container
from textual.widgets import DataTable, Static
from rich.text import Text

if TYPE_CHECKING:
    from textual.app import App


class PanelState(Enum):
    """Panel visibility states."""
    VISIBLE = auto()      # Normal visibility
    HIDDEN = auto()       # Completely hidden (display: none)
    MINIMIZED = auto()    # Collapsed to header only
    MAXIMIZED = auto()    # Fullscreen mode
    FOCUSED = auto()      # Has keyboard focus


@dataclass
class PanelConfig:
    """Configuration for a panel instance."""
    id: str                                    # Unique panel identifier
    title: str                                 # Display title
    icon: str = ""                             # Optional icon/emoji
    shortcut: str = ""                         # Keyboard shortcut (e.g., "1")
    color: str = "#58a6ff"                     # Title color
    priority: int = 50                         # Layout priority (higher = more important)
    min_height: int = 3                        # Minimum height in rows
    min_width: int = 20                        # Minimum width in columns
    default_state: PanelState = PanelState.VISIBLE
    resizable: bool = True
    columns: List[str] = field(default_factory=list)  # DataTable columns

    def __post_init__(self):
        if not self.columns:
            self.columns = []


@dataclass
class PanelDimensions:
    """Current dimensions of a panel."""
    width: int = 0
    height: int = 0
    x: int = 0
    y: int = 0
    row: int = 0
    col: int = 0


class Panel(ABC):
    """
    Abstract base class for all TUI panels.

    Panels are the building blocks of the TUI interface. Each panel:
    - Has a unique ID and configuration
    - Can be shown, hidden, minimized, or maximized
    - Manages its own data and rendering
    - Responds to mode changes via CSS class toggles
    - Handles its own data updates efficiently

    Subclasses must implement:
    - compose(): Return the Textual widgets for this panel
    - on_data_update(): Handle incoming data events
    - get_selected_item(): Return currently selected data item
    """

    def __init__(self, config: PanelConfig, app: Optional["App"] = None):
        self.config = config
        self.app = app
        self._state = config.default_state
        self._dimensions = PanelDimensions()
        self._container: Optional[Container] = None
        self._table: Optional[DataTable] = None
        self._title_widget: Optional[Static] = None
        self._data: List[Any] = []
        self._data_hash: set = set()  # For deduplication
        self._callbacks: Dict[str, List[Callable]] = {}
        self._last_update_count = 0

    @property
    def id(self) -> str:
        """Panel unique identifier."""
        return self.config.id

    @property
    def state(self) -> PanelState:
        """Current panel state."""
        return self._state

    @property
    def is_visible(self) -> bool:
        """Whether panel is currently visible."""
        return self._state in (PanelState.VISIBLE, PanelState.FOCUSED, PanelState.MAXIMIZED)

    @property
    def is_focused(self) -> bool:
        """Whether panel currently has focus."""
        return self._state == PanelState.FOCUSED

    @property
    def data_count(self) -> int:
        """Number of data items in this panel."""
        return len(self._data)

    # ===== STATE MANAGEMENT =====

    def show(self) -> None:
        """Show the panel (set to VISIBLE state)."""
        self._set_state(PanelState.VISIBLE)
        self._apply_css_classes()

    def hide(self) -> None:
        """Hide the panel completely."""
        self._set_state(PanelState.HIDDEN)
        self._apply_css_classes()

    def minimize(self) -> None:
        """Minimize panel to header only."""
        self._set_state(PanelState.MINIMIZED)
        self._apply_css_classes()

    def maximize(self) -> None:
        """Maximize panel to fullscreen."""
        self._set_state(PanelState.MAXIMIZED)
        self._apply_css_classes()

    def focus(self) -> None:
        """Give focus to this panel."""
        self._set_state(PanelState.FOCUSED)
        self._apply_css_classes()
        if self._table:
            self._table.focus()

    def unfocus(self) -> None:
        """Remove focus from this panel."""
        if self._state == PanelState.FOCUSED:
            self._set_state(PanelState.VISIBLE)
            self._apply_css_classes()

    def toggle_visibility(self) -> None:
        """Toggle between visible and hidden states."""
        if self.is_visible:
            self.hide()
        else:
            self.show()

    def _set_state(self, new_state: PanelState) -> None:
        """Internal state setter with callback invocation."""
        old_state = self._state
        self._state = new_state
        self._trigger_callback("state_change", old_state, new_state)

    def _apply_css_classes(self) -> None:
        """Apply CSS classes based on current state."""
        if not self._container:
            return

        # Remove all state classes
        for state in PanelState:
            class_name = f"panel-{state.name.lower()}"
            self._container.remove_class(class_name)

        # Add current state class
        class_name = f"panel-{self._state.name.lower()}"
        self._container.add_class(class_name)

        # Handle special display states
        if self._state == PanelState.HIDDEN:
            self._container.add_class("hidden")
        else:
            self._container.remove_class("hidden")

    # ===== RESIZE =====

    def resize(self, width: int, height: int) -> None:
        """
        Resize the panel to new dimensions.

        Args:
            width: New width in columns
            height: New height in rows
        """
        self._dimensions.width = max(width, self.config.min_width)
        self._dimensions.height = max(height, self.config.min_height)
        self._apply_dimensions()
        self._trigger_callback("resize", self._dimensions)

    def set_position(self, x: int, y: int, row: int = 0, col: int = 0) -> None:
        """Set panel position in the layout grid."""
        self._dimensions.x = x
        self._dimensions.y = y
        self._dimensions.row = row
        self._dimensions.col = col

    def _apply_dimensions(self) -> None:
        """Apply current dimensions to container."""
        if not self._container:
            return
        # Textual handles this via CSS, but we can store for responsive calculations

    # ===== WIDGET CREATION =====

    def compose(self) -> Container:
        """
        Create and return the panel container with all widgets.

        Returns:
            Container widget with title and data table
        """
        self._container = Container(id=f"{self.id}-pane", classes="panel-container")
        self._title_widget = self._create_title()
        self._table = self._create_table()

        # Build the container
        self._container.compose_add_child(self._title_widget)
        self._container.compose_add_child(self._table)

        self._apply_css_classes()
        return self._container

    def _create_title(self) -> Static:
        """Create the title bar widget."""
        shortcut = f"[{self.config.shortcut}] " if self.config.shortcut else ""
        icon = f"{self.config.icon} " if self.config.icon else ""
        title_text = Text()
        title_text.append(f" {shortcut}{icon}{self.config.title} ", style=f"bold {self.config.color}")
        return Static(title_text, classes="pane-title")

    def _create_table(self) -> DataTable:
        """Create the data table widget."""
        table = DataTable(id=f"{self.id}-table")
        table.cursor_type = "row"
        table.zebra_stripes = True

        # Add configured columns
        for col in self.config.columns:
            table.add_column(col)

        return table

    # ===== DATA MANAGEMENT =====

    @abstractmethod
    def on_data_update(self, data: Any) -> None:
        """
        Handle incoming data event.

        Subclasses must implement this to process their specific data type.

        Args:
            data: New data item to process
        """
        pass

    @abstractmethod
    def get_selected_item(self) -> Optional[Any]:
        """
        Get the currently selected data item.

        Returns:
            The selected item, or None if nothing selected
        """
        pass

    def add_data(self, item: Any, dedupe_key: Optional[str] = None) -> bool:
        """
        Add a data item to the panel.

        Args:
            item: Data item to add
            dedupe_key: Optional key for deduplication

        Returns:
            True if item was added, False if duplicate
        """
        if dedupe_key:
            if dedupe_key in self._data_hash:
                return False
            self._data_hash.add(dedupe_key)

        self._data.append(item)
        self._trigger_callback("data_added", item)
        return True

    def clear_data(self) -> None:
        """Clear all data from the panel."""
        self._data.clear()
        self._data_hash.clear()
        if self._table:
            self._table.clear()
        self._trigger_callback("data_cleared")

    def refresh_table(self, limit: int = 200) -> None:
        """
        Refresh the table display from current data.

        Args:
            limit: Maximum rows to display
        """
        if not self._table:
            return

        # Only refresh if data changed significantly
        if len(self._data) == self._last_update_count:
            return

        self._last_update_count = len(self._data)
        self._render_rows(limit)

    @abstractmethod
    def _render_rows(self, limit: int) -> None:
        """
        Render data rows to the table.

        Subclasses implement this to format their specific data.

        Args:
            limit: Maximum rows to render
        """
        pass

    # ===== CALLBACKS =====

    def on(self, event: str, callback: Callable) -> None:
        """
        Register a callback for panel events.

        Events:
            - state_change: (old_state, new_state)
            - resize: (dimensions)
            - data_added: (item)
            - data_cleared: ()
            - row_selected: (item, index)
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
                pass  # Don't let callback errors break the panel

    # ===== CSS GENERATION =====

    @classmethod
    def get_base_css(cls) -> str:
        """
        Get the base CSS for all panels.

        Returns:
            CSS string for panel styling
        """
        return """
        .panel-container {
            width: 100%;
            height: 100%;
        }

        .panel-hidden {
            display: none;
        }

        .panel-minimized {
            height: 1;
        }

        .panel-minimized DataTable {
            display: none;
        }

        .panel-maximized {
            width: 100%;
            height: 100%;
            layer: fullscreen;
            dock: top;
        }

        .panel-focused {
            border: tall $accent;
        }

        .pane-title {
            height: 1;
            width: 100%;
            background: $surface;
            padding: 0 1;
        }
        """

    # ===== UTILITY METHODS =====

    def get_container(self) -> Optional[Container]:
        """Get the panel's container widget."""
        return self._container

    def get_table(self) -> Optional[DataTable]:
        """Get the panel's data table widget."""
        return self._table

    def has_focus(self) -> bool:
        """Check if the panel's table has focus."""
        return self._table.has_focus if self._table else False

    def get_cursor_row(self) -> Optional[int]:
        """Get the current cursor row index."""
        return self._table.cursor_row if self._table else None
