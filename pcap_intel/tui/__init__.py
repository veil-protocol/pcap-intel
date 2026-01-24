"""
PCAP-Intel Modular TUI System

A clean, modular architecture for the intelligence display interface.
Supports multiple view modes, responsive layouts, and theming.

v2.0 Features:
- Session persistence with encrypted storage
- Advanced BPF-style filtering
- Behavioral timeline panel
"""

from .panels.base import Panel, PanelState, PanelConfig
from .modes.manager import ModeManager
from .modes.presets import ViewMode, MODE_PRESETS
from .themes.manager import ThemeManager, Theme
from .layout.responsive import ResponsiveContainer, Breakpoint

# v2.0: Session Persistence
from .session_storage import SessionStorage, create_session_storage

# v2.0: Advanced Filtering
from .advanced_filter import AdvancedFilter, FILTER_PRESETS

# v2.0: Timeline Panel
from .timeline_panel import TimelinePanel, TimelineEvent, ActivitySession

__all__ = [
    # Panels
    "Panel",
    "PanelState",
    "PanelConfig",
    # Modes
    "ModeManager",
    "ViewMode",
    "MODE_PRESETS",
    # Themes
    "ThemeManager",
    "Theme",
    # Layout
    "ResponsiveContainer",
    "Breakpoint",
    # v2.0: Session Persistence
    "SessionStorage",
    "create_session_storage",
    # v2.0: Advanced Filtering
    "AdvancedFilter",
    "FILTER_PRESETS",
    # v2.0: Timeline Panel
    "TimelinePanel",
    "TimelineEvent",
    "ActivitySession",
]
