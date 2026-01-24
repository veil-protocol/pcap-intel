"""
Modular PCAP-Intel TUI Application

Integrates panels, modes, themes, and responsive layout into a cohesive application.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, DataTable, RichLog
from textual.binding import Binding
from rich.text import Text

from .panels import (
    Panel, PanelConfig,
    CredentialsPanel, FlowsPanel, DNSPanel, HostsPanel, AlertsPanel
)
from .modes import ModeManager, ViewMode, MODE_PRESETS
from .themes import ThemeManager, Theme
from .layout import ResponsiveContainer, Breakpoint


class ModularPcapIntelApp(App):
    """
    Modular PCAP-Intel TUI Application.

    Features:
    - Pluggable panel system
    - Multiple view modes
    - Theme switching
    - Responsive layout
    - Keyboard shortcuts
    """

    BINDINGS = [
        # Core bindings
        Binding("q", "quit", "Quit", priority=True),
        Binding("escape", "escape", "Back", priority=True),

        # Panel focus bindings
        Binding("1", "focus_panel('creds')", "Creds", priority=True),
        Binding("2", "focus_panel('flows')", "Flows", priority=True),
        Binding("3", "focus_panel('dns')", "DNS", priority=True),
        Binding("4", "focus_panel('hosts')", "Hosts", priority=True),
        Binding("5", "focus_panel('alerts')", "Alerts", priority=True),

        # Operational mode bindings (F1-F5)
        Binding("f1", "set_op_mode('red_team')", "RED", priority=True),
        Binding("f2", "set_op_mode('blue_team')", "BLUE", priority=True),
        Binding("f3", "set_op_mode('network_recon')", "RECON", priority=True),
        Binding("f4", "set_op_mode('situational')", "SITU", priority=True),
        Binding("f5", "set_op_mode('compromised_host')", "COMP", priority=True),

        # View mode bindings
        Binding("m", "cycle_mode", "Mode", priority=True),
        Binding("f", "toggle_fullscreen", "Full", priority=True),

        # Theme bindings
        Binding("t", "cycle_theme", "Theme", priority=True),

        # Actions
        Binding("c", "copy", "Copy", priority=True),
        Binding("e", "export", "Export", priority=True),
        Binding("d", "toggle_debug", "Debug", priority=True),
        Binding("space", "pause", "Pause", priority=True),
    ]

    TITLE = "PCAP-INTEL"

    def __init__(
        self,
        interface: str = None,
        pcap_file: str = None,
        bpf_filter: str = "",
        debug: bool = False,
        theme: str = "github-dark",
        mode: ViewMode = ViewMode.STANDARD,
    ):
        super().__init__()
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.debug_mode = debug

        # Initialize managers
        self.theme_manager = ThemeManager(default_theme=theme)
        self.mode_manager = ModeManager()
        self.responsive = ResponsiveContainer(mode_manager=self.mode_manager)

        # Create panels
        self._create_panels()

        # State
        self.packets = 0
        self.start_time = None
        self.paused = False
        self._last_ui_update = 0

        # Set initial mode
        self._initial_mode = mode

    def _create_panels(self) -> None:
        """Create and register all panels."""
        self.panels: Dict[str, Panel] = {}

        # Create default panels
        self.panels["creds"] = CredentialsPanel.create_default(self)
        self.panels["flows"] = FlowsPanel.create_default(self)
        self.panels["dns"] = DNSPanel.create_default(self)
        self.panels["hosts"] = HostsPanel.create_default(self)
        self.panels["alerts"] = AlertsPanel.create_default(self)

        # Register with managers
        self.mode_manager.register_panels(list(self.panels.values()))
        for panel in self.panels.values():
            self.responsive.register_panel(panel)

    @property
    def CSS(self) -> str:
        """Dynamic CSS based on current theme."""
        return self.theme_manager.get_full_css()

    def compose(self) -> ComposeResult:
        """Compose the application UI."""
        yield Header()
        yield Static(id="stats")

        with Vertical(id="main"):
            # Row 1: Credentials and Flows
            with Horizontal(id="row1"):
                with Container(id="creds-pane"):
                    yield Static(self._get_panel_title("creds"), classes="pane-title")
                    yield DataTable(id="creds-table")
                with Container(id="flows-pane"):
                    yield Static(self._get_panel_title("flows"), classes="pane-title")
                    yield DataTable(id="flows-table")

            # Row 2: DNS and Hosts
            with Horizontal(id="row2"):
                with Container(id="dns-pane"):
                    yield Static(self._get_panel_title("dns"), classes="pane-title")
                    yield DataTable(id="dns-table")
                with Container(id="hosts-pane"):
                    yield Static(self._get_panel_title("hosts"), classes="pane-title")
                    yield DataTable(id="hosts-table")

            # Row 3: Alerts
            with Container(id="row3"):
                with Container(id="alerts-pane"):
                    yield Static(self._get_panel_title("alerts"), classes="pane-title")
                    yield DataTable(id="alerts-table")

        # Detail overlay for fullscreen mode
        with Container(id="detail-overlay"):
            yield Static("", id="detail-header")
            with Horizontal(id="detail-content"):
                with Container(id="detail-left"):
                    yield DataTable(id="detail-table")
                with Container(id="detail-right"):
                    yield Static("", id="detail-info")
                    with Container(id="detail-related"):
                        yield RichLog(id="detail-log")
            yield Static(" [ESC/f] Close  [c] Copy ", id="detail-footer")

        # Debug overlay
        with Container(id="debug-overlay"):
            yield RichLog(id="debug-log")

        yield Footer()

    def _get_panel_title(self, panel_id: str) -> Text:
        """Generate panel title with shortcut."""
        panel = self.panels.get(panel_id)
        if not panel:
            return Text(panel_id.upper())

        config = panel.config
        shortcut = f"[{config.shortcut}] " if config.shortcut else ""
        title_text = Text()
        title_text.append(f" {shortcut}{config.title} ", style=f"bold {config.color}")
        return title_text

    def on_mount(self) -> None:
        """Initialize application after mount."""
        self.start_time = datetime.now()

        # Setup tables
        self._setup_tables()

        # Apply initial mode
        self.mode_manager.set_mode(self._initial_mode)

        # Register callbacks
        self._setup_callbacks()

        # Update stats
        self._update_stats()

        # Focus first panel
        self.query_one("#creds-table", DataTable).focus()

        # Start data pipeline (if available)
        # self.run_worker(self._run_pipeline())

    def _setup_tables(self) -> None:
        """Configure data tables."""
        tables = {
            "creds": ["PROTO", "USER", "DOMAIN", "TARGET"],
            "flows": ["SRC -> DST", "PORT", "CNT"],
            "dns": ["DOMAIN", "IP"],
            "hosts": ["IP", "OS", "SVCS"],
            "alerts": ["SEV", "TYPE", "MESSAGE", "TARGET"],
            "detail": [],  # Columns set dynamically
        }

        for table_id, columns in tables.items():
            try:
                table = self.query_one(f"#{table_id}-table", DataTable)
                table.cursor_type = "row"
                table.zebra_stripes = True
                for col in columns:
                    table.add_column(col)
            except Exception:
                pass

    def _setup_callbacks(self) -> None:
        """Setup callbacks for managers."""
        # Theme change callback
        def on_theme_change(old, new):
            self.refresh_css()

        self.theme_manager.on("theme_changed", on_theme_change)

        # Mode change callback
        def on_mode_change(old, new):
            self._apply_mode_visibility()

        self.mode_manager.on("mode_changed", on_mode_change)

        # Responsive callbacks
        def on_breakpoint_change(old, new):
            self._log_debug(f"Breakpoint: {old.name} -> {new.name}")

        self.responsive.on("breakpoint_changed", on_breakpoint_change)

    def _apply_mode_visibility(self) -> None:
        """Apply panel visibility based on current mode."""
        preset = self.mode_manager.current_preset

        for panel_id, layout in preset.panels.items():
            try:
                pane = self.query_one(f"#{panel_id}-pane")
                if layout.visible:
                    pane.remove_class("hidden")
                else:
                    pane.add_class("hidden")
            except Exception:
                pass

    def _update_stats(self) -> None:
        """Update the stats bar."""
        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        rate = self.packets / elapsed if elapsed > 0 else 0

        stats = self.query_one("#stats", Static)
        t = Text()
        t.append(f" {self.packets:,} pkt ", style="#7ee787")
        t.append(f"({rate:.0f}/s) ", style="dim")
        t.append("| ", style="#30363d")

        # Panel counts
        for panel_id, panel in self.panels.items():
            count = panel.data_count
            color = panel.config.color
            style = f"bold {color}" if count > 0 else "dim"
            t.append(f"{panel_id.upper()[:4]}:{count} ", style=style)

        # Status indicators
        if self.paused:
            t.append("| PAUSED", style="bold #bf8700")

        mode_name = self.mode_manager.current_preset.name
        t.append(f" | Mode: {mode_name}", style="dim")

        stats.update(t)

    def _log_debug(self, msg: str) -> None:
        """Log debug message."""
        if self.debug_mode:
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            try:
                log = self.query_one("#debug-log", RichLog)
                log.write(f"[dim]{ts}[/] {msg}")
            except Exception:
                pass

    # ===== ACTIONS =====

    def action_focus_panel(self, panel_id: str) -> None:
        """Focus a specific panel."""
        if self.mode_manager.is_fullscreen():
            return

        try:
            table = self.query_one(f"#{panel_id}-table", DataTable)
            table.focus()
            self.mode_manager.focus_panel(panel_id)
        except Exception:
            pass

    def action_cycle_mode(self) -> None:
        """Cycle through view modes."""
        modes = [ViewMode.STANDARD, ViewMode.CREDENTIALS, ViewMode.NETWORK, ViewMode.MINIMAL]
        self.mode_manager.cycle_modes(modes)
        self._update_stats()

    def action_set_op_mode(self, mode_name: str) -> None:
        """Set an operational mode (F1-F5)."""
        # Mode name to ViewMode mapping
        op_mode_map = {
            "red_team": ViewMode.RED_TEAM,
            "blue_team": ViewMode.BLUE_TEAM,
            "network_recon": ViewMode.NETWORK_RECON,
            "situational": ViewMode.SITUATIONAL,
            "compromised_host": ViewMode.COMPROMISED_HOST,
        }

        # Mode to theme mapping for automatic theme switching
        mode_theme_map = {
            "red_team": "red-team",
            "blue_team": "blue-team",
            "network_recon": "network-recon",
            "situational": "github-dark",
            "compromised_host": "compromised-host",
        }

        view_mode = op_mode_map.get(mode_name)
        if view_mode:
            self.mode_manager.set_mode(view_mode)

            # Auto-switch theme for operational modes
            theme_name = mode_theme_map.get(mode_name)
            if theme_name:
                self.theme_manager.set_theme(theme_name)

            self._log_debug(f"Mode: {mode_name.upper()}")
            self._update_stats()

    def action_toggle_fullscreen(self) -> None:
        """Toggle fullscreen for focused panel."""
        if self.mode_manager.is_fullscreen():
            self.mode_manager.exit_fullscreen()
            self.query_one("#detail-overlay").remove_class("visible")
        else:
            focused = self.mode_manager.get_focused_panel()
            if focused:
                self.mode_manager.enter_fullscreen(focused)
                self.query_one("#detail-overlay").add_class("visible")
                self._show_fullscreen_detail(focused)

    def _show_fullscreen_detail(self, panel_id: str) -> None:
        """Show fullscreen detail view for a panel."""
        panel = self.panels.get(panel_id)
        if not panel:
            return

        # Update header
        header = self.query_one("#detail-header", Static)
        header.update(f" {panel.config.title} - FULLSCREEN ")

    def action_escape(self) -> None:
        """Handle escape key."""
        if self.mode_manager.is_fullscreen():
            self.mode_manager.exit_fullscreen()
            self.query_one("#detail-overlay").remove_class("visible")

    def action_cycle_theme(self) -> None:
        """Cycle through themes."""
        themes = ["github-dark", "dracula", "nord", "monokai"]
        new_theme = self.theme_manager.cycle_themes(themes)
        self._log_debug(f"Theme: {new_theme}")

    def action_copy(self) -> None:
        """Copy selected item to clipboard."""
        try:
            import pyperclip
        except ImportError:
            return

        focused = self.mode_manager.get_focused_panel()
        if not focused:
            return

        panel = self.panels.get(focused)
        if panel:
            item = panel.get_selected_item()
            if item:
                # Format depends on panel type
                if focused == "creds":
                    text = getattr(item, "hashcat_format", str(item))
                else:
                    text = str(item)
                try:
                    pyperclip.copy(text)
                    self._log_debug(f"Copied: {text[:50]}...")
                except Exception:
                    pass

    def action_export(self) -> None:
        """Export credentials to file."""
        creds_panel = self.panels.get("creds")
        if creds_panel:
            hashes = creds_panel.get_hashcat_hashes()
            if hashes:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"hashes_{ts}.txt"
                with open(filename, "w") as f:
                    f.write("\n".join(hashes))
                self._log_debug(f"Exported {len(hashes)} hashes to {filename}")

    def action_toggle_debug(self) -> None:
        """Toggle debug overlay."""
        overlay = self.query_one("#debug-overlay")
        if "visible" in overlay.classes:
            overlay.remove_class("visible")
            self.debug_mode = False
        else:
            overlay.add_class("visible")
            self.debug_mode = True

    def action_pause(self) -> None:
        """Toggle pause state."""
        self.paused = not self.paused
        self._update_stats()

    # ===== DATA HANDLING =====

    def handle_event(self, event_type: str, data: Any) -> None:
        """
        Handle incoming data events.

        Routes events to appropriate panels.
        """
        if event_type == "packet":
            self.packets += 1
            if self.packets % 100 == 0:
                self._update_stats()

        elif event_type == "credential":
            self.panels["creds"].on_data_update(data)
            # Cross-reference with hosts
            self.panels["hosts"].add_credential(data)

        elif event_type == "alert":
            self.panels["alerts"].on_data_update(data)

        elif event_type == "entity":
            etype = getattr(data, "type", "")
            if etype == "flow":
                self.panels["flows"].on_data_update(data)
            elif etype == "dns_resolution":
                self.panels["dns"].on_data_update(data)
            elif etype in ("os_fingerprint", "service", "host"):
                self.panels["hosts"].on_data_update(data)

    def on_resize(self, event) -> None:
        """Handle terminal resize."""
        self.responsive.on_resize(event.size.width, event.size.height)


def run_modular_tui(
    interface: str = None,
    pcap_file: str = None,
    bpf_filter: str = "",
    debug: bool = False,
    theme: str = "github-dark",
    mode: str = "standard",
) -> None:
    """
    Run the modular PCAP-Intel TUI.

    Args:
        interface: Network interface to capture from
        pcap_file: PCAP file to analyze
        bpf_filter: BPF filter string
        debug: Enable debug mode
        theme: Initial theme name
        mode: Initial view mode (standard, credentials, network, minimal,
              red_team, blue_team, network_recon, situational, compromised_host)
    """
    mode_map = {
        # Layout modes
        "standard": ViewMode.STANDARD,
        "credentials": ViewMode.CREDENTIALS,
        "network": ViewMode.NETWORK,
        "minimal": ViewMode.MINIMAL,
        "analyst": ViewMode.ANALYST,
        "timeline": ViewMode.TIMELINE,
        # Operational modes
        "red_team": ViewMode.RED_TEAM,
        "red": ViewMode.RED_TEAM,
        "blue_team": ViewMode.BLUE_TEAM,
        "blue": ViewMode.BLUE_TEAM,
        "network_recon": ViewMode.NETWORK_RECON,
        "recon": ViewMode.NETWORK_RECON,
        "situational": ViewMode.SITUATIONAL,
        "situ": ViewMode.SITUATIONAL,
        "compromised_host": ViewMode.COMPROMISED_HOST,
        "compromised": ViewMode.COMPROMISED_HOST,
    }

    # Auto-select theme for operational modes
    mode_theme_map = {
        "red_team": "red-team",
        "red": "red-team",
        "blue_team": "blue-team",
        "blue": "blue-team",
        "network_recon": "network-recon",
        "recon": "network-recon",
        "compromised_host": "compromised-host",
        "compromised": "compromised-host",
    }

    view_mode = mode_map.get(mode.lower(), ViewMode.STANDARD)

    # Auto-apply theme for operational modes
    if mode.lower() in mode_theme_map:
        theme = mode_theme_map[mode.lower()]

    app = ModularPcapIntelApp(
        interface=interface,
        pcap_file=pcap_file,
        bpf_filter=bpf_filter,
        debug=debug,
        theme=theme,
        mode=view_mode,
    )
    app.run()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Modular PCAP-INTEL TUI")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-i", "--interface", help="Network interface")
    source.add_argument("-r", "--pcap", dest="pcap_file", help="PCAP file")
    parser.add_argument("-f", "--filter", dest="bpf_filter", default="", help="BPF filter")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("-t", "--theme", default="github-dark", help="Theme name")
    parser.add_argument("-m", "--mode", default="standard", help="View mode")

    args = parser.parse_args()
    run_modular_tui(
        interface=args.interface,
        pcap_file=args.pcap_file,
        bpf_filter=args.bpf_filter,
        debug=args.debug,
        theme=args.theme,
        mode=args.mode,
    )
