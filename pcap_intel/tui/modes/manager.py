"""
Mode Manager - Controls panel visibility and layout based on view modes.

Handles mode switching, CSS class management, and space redistribution.
"""

from typing import Callable, Dict, List, Optional, TYPE_CHECKING

from .presets import ViewMode, ModePreset, PanelLayout, MODE_PRESETS, get_preset

if TYPE_CHECKING:
    from ..panels.base import Panel


class ModeManager:
    """
    Manages view modes and panel layouts.

    The ModeManager is responsible for:
    - Switching between predefined view modes
    - Applying panel visibility and layout configurations
    - Managing CSS class toggles
    - Handling fullscreen/maximized states
    - Coordinating space redistribution
    """

    def __init__(self, panels: Optional[Dict[str, "Panel"]] = None):
        """
        Initialize the mode manager.

        Args:
            panels: Dictionary of panel_id -> Panel instances
        """
        self._panels: Dict[str, "Panel"] = panels or {}
        self._current_mode = ViewMode.STANDARD
        self._current_preset = get_preset(ViewMode.STANDARD)
        self._previous_mode: Optional[ViewMode] = None
        self._fullscreen_panel: Optional[str] = None
        self._callbacks: Dict[str, List[Callable]] = {}

    @property
    def current_mode(self) -> ViewMode:
        """Get the current view mode."""
        return self._current_mode

    @property
    def current_preset(self) -> ModePreset:
        """Get the current mode preset configuration."""
        return self._current_preset

    @property
    def visible_panels(self) -> List[str]:
        """Get list of currently visible panel IDs."""
        return [
            pid for pid, layout in self._current_preset.panels.items()
            if layout.visible
        ]

    def register_panel(self, panel: "Panel") -> None:
        """
        Register a panel with the mode manager.

        Args:
            panel: Panel instance to register
        """
        self._panels[panel.id] = panel

    def register_panels(self, panels: List["Panel"]) -> None:
        """
        Register multiple panels.

        Args:
            panels: List of Panel instances
        """
        for panel in panels:
            self.register_panel(panel)

    # ===== MODE SWITCHING =====

    def set_mode(self, mode: ViewMode) -> None:
        """
        Switch to a new view mode.

        Args:
            mode: ViewMode to switch to
        """
        if mode == self._current_mode and mode != ViewMode.FULLSCREEN:
            return

        self._previous_mode = self._current_mode
        self._current_mode = mode
        self._current_preset = get_preset(mode)

        self._apply_mode()
        self._trigger_callback("mode_changed", self._previous_mode, mode)

    def toggle_mode(self, mode: ViewMode) -> None:
        """
        Toggle between a mode and the previous mode.

        Args:
            mode: ViewMode to toggle to/from
        """
        if self._current_mode == mode and self._previous_mode:
            self.set_mode(self._previous_mode)
        else:
            self.set_mode(mode)

    def restore_previous_mode(self) -> None:
        """Restore the previous view mode."""
        if self._previous_mode:
            self.set_mode(self._previous_mode)

    def cycle_modes(self, modes: Optional[List[ViewMode]] = None) -> None:
        """
        Cycle through available modes.

        Args:
            modes: Optional list of modes to cycle through (defaults to all)
        """
        if modes is None:
            modes = [ViewMode.STANDARD, ViewMode.CREDENTIALS, ViewMode.NETWORK, ViewMode.MINIMAL]

        try:
            current_idx = modes.index(self._current_mode)
            next_idx = (current_idx + 1) % len(modes)
        except ValueError:
            next_idx = 0

        self.set_mode(modes[next_idx])

    def _apply_mode(self) -> None:
        """Apply the current mode's configuration to all panels."""
        preset = self._current_preset

        for panel_id, layout in preset.panels.items():
            panel = self._panels.get(panel_id)
            if not panel:
                continue

            if layout.visible:
                panel.show()
            else:
                panel.hide()

            if layout.minimized:
                panel.minimize()

            # Apply CSS classes
            self._apply_panel_css(panel, layout)

        # Update container CSS
        self._update_container_css()

    def _apply_panel_css(self, panel: "Panel", layout: PanelLayout) -> None:
        """Apply CSS classes to a panel based on layout."""
        container = panel.get_container()
        if not container:
            return

        # Remove old layout classes
        for cls in list(container.classes):
            if cls.startswith("layout-"):
                container.remove_class(cls)

        # Add new layout classes
        container.add_class(f"layout-row-{layout.row}")
        container.add_class(f"layout-col-{layout.col}")

        if layout.row_span > 1:
            container.add_class(f"layout-rowspan-{layout.row_span}")
        if layout.col_span > 1:
            container.add_class(f"layout-colspan-{layout.col_span}")

        # Add custom CSS classes
        for cls in layout.css_classes:
            container.add_class(cls)

    def _update_container_css(self) -> None:
        """Update the main container CSS class for the current mode."""
        # This would be called on the app's main container
        # Implementation depends on app structure
        pass

    # ===== FULLSCREEN HANDLING =====

    def enter_fullscreen(self, panel_id: str) -> bool:
        """
        Enter fullscreen mode with a specific panel.

        Args:
            panel_id: ID of the panel to maximize

        Returns:
            True if successful, False if panel not found
        """
        if panel_id not in self._panels:
            return False

        self._previous_mode = self._current_mode
        self._fullscreen_panel = panel_id

        # Create fullscreen preset with this panel visible
        preset = get_preset(ViewMode.FULLSCREEN)
        for pid, layout in preset.panels.items():
            layout.visible = (pid == panel_id)

        self._current_mode = ViewMode.FULLSCREEN
        self._current_preset = preset

        # Maximize the panel
        self._panels[panel_id].maximize()

        # Hide all others
        for pid, panel in self._panels.items():
            if pid != panel_id:
                panel.hide()

        self._trigger_callback("fullscreen_entered", panel_id)
        return True

    def exit_fullscreen(self) -> None:
        """Exit fullscreen mode and restore previous layout."""
        if self._current_mode != ViewMode.FULLSCREEN:
            return

        self._fullscreen_panel = None

        if self._previous_mode:
            self.set_mode(self._previous_mode)
        else:
            self.set_mode(ViewMode.STANDARD)

        self._trigger_callback("fullscreen_exited")

    def is_fullscreen(self) -> bool:
        """Check if currently in fullscreen mode."""
        return self._current_mode == ViewMode.FULLSCREEN

    def get_fullscreen_panel(self) -> Optional[str]:
        """Get the ID of the currently fullscreen panel."""
        return self._fullscreen_panel

    # ===== PANEL VISIBILITY =====

    def show_panel(self, panel_id: str) -> None:
        """
        Show a specific panel (temporary override of mode).

        Args:
            panel_id: ID of the panel to show
        """
        if panel_id in self._panels:
            self._panels[panel_id].show()

    def hide_panel(self, panel_id: str) -> None:
        """
        Hide a specific panel (temporary override of mode).

        Args:
            panel_id: ID of the panel to hide
        """
        if panel_id in self._panels:
            self._panels[panel_id].hide()

    def toggle_panel(self, panel_id: str) -> None:
        """
        Toggle a panel's visibility.

        Args:
            panel_id: ID of the panel to toggle
        """
        if panel_id in self._panels:
            self._panels[panel_id].toggle_visibility()

    def focus_panel(self, panel_id: str) -> bool:
        """
        Focus a specific panel.

        Args:
            panel_id: ID of the panel to focus

        Returns:
            True if successful
        """
        if panel_id not in self._panels:
            return False

        # Unfocus all others
        for pid, panel in self._panels.items():
            if pid != panel_id:
                panel.unfocus()

        self._panels[panel_id].focus()
        self._trigger_callback("panel_focused", panel_id)
        return True

    def get_focused_panel(self) -> Optional[str]:
        """Get the ID of the currently focused panel."""
        for pid, panel in self._panels.items():
            if panel.is_focused or panel.has_focus():
                return pid
        return None

    # ===== LAYOUT CUSTOMIZATION =====

    def set_panel_layout(self, panel_id: str, layout: PanelLayout) -> None:
        """
        Set custom layout for a panel.

        Args:
            panel_id: ID of the panel
            layout: New layout configuration
        """
        if panel_id in self._current_preset.panels:
            self._current_preset.panels[panel_id] = layout
            self._apply_mode()

    def get_panel_layout(self, panel_id: str) -> Optional[PanelLayout]:
        """Get the current layout for a panel."""
        return self._current_preset.panels.get(panel_id)

    # ===== CALLBACKS =====

    def on(self, event: str, callback: Callable) -> None:
        """
        Register a callback for mode events.

        Events:
            - mode_changed: (old_mode, new_mode)
            - fullscreen_entered: (panel_id)
            - fullscreen_exited: ()
            - panel_focused: (panel_id)
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

    # ===== CSS GENERATION =====

    def get_mode_css(self) -> str:
        """
        Generate CSS for all view modes.

        Returns:
            CSS string for mode-based styling
        """
        css_parts = []

        for mode, preset in MODE_PRESETS.items():
            mode_css = f"""
            /* {preset.name} Mode */
            .{preset.css_class} {{
                /* Grid configuration */
            }}
            """
            css_parts.append(mode_css)

            # Generate panel-specific CSS
            for panel_id, layout in preset.panels.items():
                if not layout.visible:
                    css_parts.append(f"""
                    .{preset.css_class} #{panel_id}-pane {{
                        display: none;
                    }}
                    """)
                else:
                    css_parts.append(f"""
                    .{preset.css_class} #{panel_id}-pane {{
                        width: {layout.width_percent}%;
                        height: {layout.height_percent}%;
                    }}
                    """)

        return "\n".join(css_parts)

    # ===== UTILITIES =====

    def get_mode_info(self) -> Dict:
        """Get information about the current mode."""
        return {
            "mode": self._current_mode.name,
            "name": self._current_preset.name,
            "description": self._current_preset.description,
            "visible_panels": self.visible_panels,
            "grid_rows": self._current_preset.grid_rows,
            "grid_cols": self._current_preset.grid_cols,
            "is_fullscreen": self.is_fullscreen(),
            "fullscreen_panel": self._fullscreen_panel,
        }

    def list_modes(self) -> List[Dict]:
        """List all available modes with descriptions."""
        return [
            {
                "mode": mode.name,
                "name": preset.name,
                "description": preset.description,
            }
            for mode, preset in MODE_PRESETS.items()
        ]
