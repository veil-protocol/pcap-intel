"""
View Mode Presets - Predefined panel configurations for different use cases.

Each preset defines which panels are visible, their layout, and sizing.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional


class ViewMode(Enum):
    """Available view modes."""
    # Layout-focused modes
    STANDARD = auto()       # Default 5-panel layout
    CREDENTIALS = auto()    # Focus on credentials + related
    NETWORK = auto()        # Focus on flows + hosts
    MINIMAL = auto()        # Creds + alerts only
    FULLSCREEN = auto()     # Single panel maximized
    ANALYST = auto()        # All panels, compact
    TIMELINE = auto()       # Chronological focus

    # Operational modes (F1-F5 hotkeys)
    RED_TEAM = auto()       # F1: Credential hunting, lateral movement
    BLUE_TEAM = auto()      # F2: Alert triage, anomaly detection, IOCs
    NETWORK_RECON = auto()  # F3: Host discovery, topology mapping
    SITUATIONAL = auto()    # F4: Balanced overview, all panels
    COMPROMISED_HOST = auto()  # F5: Single-host deep-dive


@dataclass
class PanelLayout:
    """Layout configuration for a single panel."""
    panel_id: str
    visible: bool = True
    row: int = 0                    # Grid row (0-indexed)
    col: int = 0                    # Grid column (0-indexed)
    row_span: int = 1               # Number of rows to span
    col_span: int = 1               # Number of columns to span
    width_percent: int = 50         # Percentage of row width
    height_percent: int = 33        # Percentage of container height
    minimized: bool = False
    css_classes: List[str] = field(default_factory=list)


@dataclass
class ModePreset:
    """Complete preset for a view mode."""
    name: str
    description: str
    panels: Dict[str, PanelLayout]
    grid_rows: int = 3              # Number of grid rows
    grid_cols: int = 2              # Number of grid columns
    css_class: str = ""             # Additional CSS class for container
    shortcuts: Dict[str, str] = field(default_factory=dict)  # key -> action


# ===== PRESET DEFINITIONS =====

MODE_PRESETS: Dict[ViewMode, ModePreset] = {

    ViewMode.STANDARD: ModePreset(
        name="Standard",
        description="Default 5-panel layout with credentials emphasis",
        grid_rows=3,
        grid_cols=2,
        css_class="mode-standard",
        panels={
            "creds": PanelLayout(
                panel_id="creds",
                row=0, col=0,
                width_percent=50,
                height_percent=33,
            ),
            "flows": PanelLayout(
                panel_id="flows",
                row=0, col=1,
                width_percent=50,
                height_percent=33,
            ),
            "dns": PanelLayout(
                panel_id="dns",
                row=1, col=0,
                width_percent=50,
                height_percent=34,
            ),
            "hosts": PanelLayout(
                panel_id="hosts",
                row=1, col=1,
                width_percent=50,
                height_percent=34,
            ),
            "alerts": PanelLayout(
                panel_id="alerts",
                row=2, col=0,
                col_span=2,
                width_percent=100,
                height_percent=33,
            ),
        },
    ),

    ViewMode.CREDENTIALS: ModePreset(
        name="Credentials Focus",
        description="Credential analysis with correlated context",
        grid_rows=2,
        grid_cols=2,
        css_class="mode-credentials",
        panels={
            "creds": PanelLayout(
                panel_id="creds",
                row=0, col=0,
                row_span=2,
                width_percent=60,
                height_percent=100,
            ),
            "hosts": PanelLayout(
                panel_id="hosts",
                row=0, col=1,
                width_percent=40,
                height_percent=50,
            ),
            "alerts": PanelLayout(
                panel_id="alerts",
                row=1, col=1,
                width_percent=40,
                height_percent=50,
            ),
            "flows": PanelLayout(
                panel_id="flows",
                visible=False,
            ),
            "dns": PanelLayout(
                panel_id="dns",
                visible=False,
            ),
        },
    ),

    ViewMode.NETWORK: ModePreset(
        name="Network Analysis",
        description="Focus on network flows and host discovery",
        grid_rows=2,
        grid_cols=2,
        css_class="mode-network",
        panels={
            "flows": PanelLayout(
                panel_id="flows",
                row=0, col=0,
                width_percent=50,
                height_percent=60,
            ),
            "hosts": PanelLayout(
                panel_id="hosts",
                row=0, col=1,
                width_percent=50,
                height_percent=60,
            ),
            "dns": PanelLayout(
                panel_id="dns",
                row=1, col=0,
                col_span=2,
                width_percent=100,
                height_percent=40,
            ),
            "creds": PanelLayout(
                panel_id="creds",
                visible=False,
            ),
            "alerts": PanelLayout(
                panel_id="alerts",
                visible=False,
            ),
        },
    ),

    ViewMode.MINIMAL: ModePreset(
        name="Minimal",
        description="Critical intel only: credentials and alerts",
        grid_rows=2,
        grid_cols=1,
        css_class="mode-minimal",
        panels={
            "creds": PanelLayout(
                panel_id="creds",
                row=0, col=0,
                width_percent=100,
                height_percent=60,
            ),
            "alerts": PanelLayout(
                panel_id="alerts",
                row=1, col=0,
                width_percent=100,
                height_percent=40,
            ),
            "flows": PanelLayout(panel_id="flows", visible=False),
            "dns": PanelLayout(panel_id="dns", visible=False),
            "hosts": PanelLayout(panel_id="hosts", visible=False),
        },
    ),

    ViewMode.ANALYST: ModePreset(
        name="Analyst",
        description="All panels visible with compact layout",
        grid_rows=3,
        grid_cols=3,
        css_class="mode-analyst",
        panels={
            "creds": PanelLayout(
                panel_id="creds",
                row=0, col=0,
                width_percent=40,
                height_percent=50,
            ),
            "flows": PanelLayout(
                panel_id="flows",
                row=0, col=1,
                width_percent=30,
                height_percent=50,
            ),
            "hosts": PanelLayout(
                panel_id="hosts",
                row=0, col=2,
                width_percent=30,
                height_percent=50,
            ),
            "dns": PanelLayout(
                panel_id="dns",
                row=1, col=0,
                col_span=2,
                width_percent=70,
                height_percent=50,
            ),
            "alerts": PanelLayout(
                panel_id="alerts",
                row=1, col=2,
                width_percent=30,
                height_percent=50,
            ),
        },
    ),

    ViewMode.TIMELINE: ModePreset(
        name="Timeline",
        description="Chronological view of events",
        grid_rows=2,
        grid_cols=1,
        css_class="mode-timeline",
        panels={
            "alerts": PanelLayout(
                panel_id="alerts",
                row=0, col=0,
                width_percent=100,
                height_percent=70,
            ),
            "creds": PanelLayout(
                panel_id="creds",
                row=1, col=0,
                width_percent=100,
                height_percent=30,
            ),
            "flows": PanelLayout(panel_id="flows", visible=False),
            "dns": PanelLayout(panel_id="dns", visible=False),
            "hosts": PanelLayout(panel_id="hosts", visible=False),
        },
    ),

    ViewMode.FULLSCREEN: ModePreset(
        name="Fullscreen",
        description="Single panel maximized (set panel separately)",
        grid_rows=1,
        grid_cols=1,
        css_class="mode-fullscreen",
        panels={
            # All panels configured as potential fullscreen targets
            # Only one will be visible at a time
            "creds": PanelLayout(
                panel_id="creds",
                row=0, col=0,
                width_percent=100,
                height_percent=100,
                visible=False,
            ),
            "flows": PanelLayout(
                panel_id="flows",
                row=0, col=0,
                width_percent=100,
                height_percent=100,
                visible=False,
            ),
            "dns": PanelLayout(
                panel_id="dns",
                row=0, col=0,
                width_percent=100,
                height_percent=100,
                visible=False,
            ),
            "hosts": PanelLayout(
                panel_id="hosts",
                row=0, col=0,
                width_percent=100,
                height_percent=100,
                visible=False,
            ),
            "alerts": PanelLayout(
                panel_id="alerts",
                row=0, col=0,
                width_percent=100,
                height_percent=100,
                visible=False,
            ),
        },
    ),

    # ===== OPERATIONAL MODES (USF Design) =====

    ViewMode.RED_TEAM: ModePreset(
        name="Red Team",
        description="Credential hunting, lateral movement paths, attack surface",
        grid_rows=2,
        grid_cols=2,
        css_class="mode-red-team",
        shortcuts={"h": "hashcat", "p": "pth", "k": "kerberos", "l": "lateral"},
        panels={
            "creds": PanelLayout(
                panel_id="creds",
                row=0, col=0,
                row_span=2,
                width_percent=60,
                height_percent=100,
                css_classes=["panel-primary"],
            ),
            "hosts": PanelLayout(
                panel_id="hosts",
                row=0, col=1,
                width_percent=40,
                height_percent=50,
            ),
            "alerts": PanelLayout(
                panel_id="alerts",
                row=1, col=1,
                width_percent=40,
                height_percent=50,
            ),
            "flows": PanelLayout(panel_id="flows", visible=False),
            "dns": PanelLayout(panel_id="dns", visible=False),
        },
    ),

    ViewMode.BLUE_TEAM: ModePreset(
        name="Blue Team",
        description="Alert triage, anomaly detection, IOC extraction",
        grid_rows=3,
        grid_cols=2,
        css_class="mode-blue-team",
        shortcuts={"t": "triage", "i": "ioc", "r": "false_positive", "e": "export_siem"},
        panels={
            "alerts": PanelLayout(
                panel_id="alerts",
                row=0, col=0,
                col_span=2,
                width_percent=100,
                height_percent=50,
                css_classes=["panel-primary"],
            ),
            "dns": PanelLayout(
                panel_id="dns",
                row=1, col=0,
                width_percent=50,
                height_percent=25,
            ),
            "flows": PanelLayout(
                panel_id="flows",
                row=1, col=1,
                width_percent=50,
                height_percent=25,
            ),
            "hosts": PanelLayout(
                panel_id="hosts",
                row=2, col=0,
                col_span=2,
                width_percent=100,
                height_percent=25,
            ),
            "creds": PanelLayout(panel_id="creds", visible=False),
        },
    ),

    ViewMode.NETWORK_RECON: ModePreset(
        name="Network Recon",
        description="Host discovery, service enumeration, topology mapping",
        grid_rows=2,
        grid_cols=2,
        css_class="mode-network-recon",
        shortcuts={"s": "services", "n": "nmap", "g": "graph", "f": "filter_subnet"},
        panels={
            "hosts": PanelLayout(
                panel_id="hosts",
                row=0, col=0,
                row_span=2,
                width_percent=50,
                height_percent=100,
                css_classes=["panel-primary"],
            ),
            "flows": PanelLayout(
                panel_id="flows",
                row=0, col=1,
                width_percent=50,
                height_percent=50,
            ),
            "dns": PanelLayout(
                panel_id="dns",
                row=1, col=1,
                width_percent=50,
                height_percent=50,
            ),
            "creds": PanelLayout(panel_id="creds", visible=False),
            "alerts": PanelLayout(panel_id="alerts", visible=False),
        },
    ),

    ViewMode.SITUATIONAL: ModePreset(
        name="Situational Awareness",
        description="Balanced overview with all panels visible",
        grid_rows=3,
        grid_cols=2,
        css_class="mode-situational",
        shortcuts={},
        panels={
            "creds": PanelLayout(
                panel_id="creds",
                row=0, col=0,
                width_percent=50,
                height_percent=33,
            ),
            "flows": PanelLayout(
                panel_id="flows",
                row=0, col=1,
                width_percent=50,
                height_percent=33,
            ),
            "dns": PanelLayout(
                panel_id="dns",
                row=1, col=0,
                width_percent=50,
                height_percent=34,
            ),
            "hosts": PanelLayout(
                panel_id="hosts",
                row=1, col=1,
                width_percent=50,
                height_percent=34,
            ),
            "alerts": PanelLayout(
                panel_id="alerts",
                row=2, col=0,
                col_span=2,
                width_percent=100,
                height_percent=33,
            ),
        },
    ),

    ViewMode.COMPROMISED_HOST: ModePreset(
        name="Compromised Host",
        description="Single-host deep-dive with activity timeline",
        grid_rows=3,
        grid_cols=2,
        css_class="mode-compromised-host",
        shortcuts={"t": "timeline", "c": "host_creds", "f": "host_flows", "r": "related"},
        panels={
            "creds": PanelLayout(
                panel_id="creds",
                row=0, col=0,
                width_percent=50,
                height_percent=40,
                css_classes=["panel-primary"],
            ),
            "flows": PanelLayout(
                panel_id="flows",
                row=0, col=1,
                row_span=2,
                width_percent=50,
                height_percent=70,
            ),
            "alerts": PanelLayout(
                panel_id="alerts",
                row=1, col=0,
                width_percent=50,
                height_percent=30,
            ),
            "hosts": PanelLayout(
                panel_id="hosts",
                row=2, col=0,
                col_span=2,
                width_percent=100,
                height_percent=30,
            ),
            "dns": PanelLayout(panel_id="dns", visible=False),
        },
    ),
}


def get_preset(mode: ViewMode) -> ModePreset:
    """Get the preset configuration for a view mode."""
    return MODE_PRESETS.get(mode, MODE_PRESETS[ViewMode.STANDARD])


def get_visible_panels(preset: ModePreset) -> List[str]:
    """Get list of visible panel IDs in a preset."""
    return [
        pid for pid, layout in preset.panels.items()
        if layout.visible
    ]


def create_custom_preset(
    name: str,
    description: str,
    visible_panels: List[str],
    base_mode: ViewMode = ViewMode.STANDARD
) -> ModePreset:
    """
    Create a custom preset based on an existing mode.

    Args:
        name: Custom preset name
        description: Description of the preset
        visible_panels: List of panel IDs to show
        base_mode: Base mode to copy layout from

    Returns:
        New ModePreset with customized visibility
    """
    base = get_preset(base_mode)
    new_panels = {}

    for pid, layout in base.panels.items():
        new_layout = PanelLayout(
            panel_id=layout.panel_id,
            visible=pid in visible_panels,
            row=layout.row,
            col=layout.col,
            row_span=layout.row_span,
            col_span=layout.col_span,
            width_percent=layout.width_percent,
            height_percent=layout.height_percent,
            minimized=layout.minimized,
            css_classes=list(layout.css_classes),
        )
        new_panels[pid] = new_layout

    return ModePreset(
        name=name,
        description=description,
        panels=new_panels,
        grid_rows=base.grid_rows,
        grid_cols=base.grid_cols,
        css_class=f"mode-custom-{name.lower().replace(' ', '-')}",
    )
