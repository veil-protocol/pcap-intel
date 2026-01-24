#!/usr/bin/env python3
"""
PCAP-INTEL TUI v2.0 Integration Module

This module provides mixin classes that add v2.0 features to the main TUI:
- Session persistence (auto-save, session recovery)
- Advanced filtering (BPF-style syntax)
- Behavioral timeline panel

Usage:
    Apply these mixins to PcapIntelApp to enable v2.0 features.

Example:
    class PcapIntelAppV2(SessionMixin, FilterMixin, TimelineMixin, PcapIntelApp):
        pass
"""

import asyncio
from typing import Dict, List, Set, Optional, Any
from datetime import datetime
from pathlib import Path

from textual.binding import Binding
from textual.widgets import Static, Input, Button
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.message import Message
from rich.text import Text
from rich.markup import render as render_markup

from .session_storage import SessionStorage, create_session_storage
from .advanced_filter import AdvancedFilter, FILTER_PRESETS
from .timeline_panel import TimelinePanel


# ===================
# Filter Input Screen
# ===================

class FilterInputScreen(ModalScreen):
    """Modal screen for entering advanced filter."""

    CSS = """
    FilterInputScreen {
        align: center middle;
    }

    #filter-dialog {
        width: 80;
        height: 20;
        border: tall #58a6ff;
        background: #0d1117;
        padding: 1 2;
    }

    #filter-title {
        text-align: center;
        text-style: bold;
        color: #58a6ff;
        margin-bottom: 1;
    }

    #filter-input {
        width: 100%;
        margin-bottom: 1;
    }

    #filter-help {
        height: 8;
        overflow-y: auto;
        color: #8b949e;
    }

    #filter-presets {
        margin-top: 1;
    }

    .preset-btn {
        margin-right: 1;
    }

    #filter-buttons {
        margin-top: 1;
        align: center middle;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("enter", "apply", "Apply"),
        Binding("ctrl+h", "show_help", "Help"),
    ]

    class FilterApplied(Message):
        """Filter applied message."""
        def __init__(self, filter_text: str):
            self.filter_text = filter_text
            super().__init__()

    def __init__(self, current_filter: str = ""):
        super().__init__()
        self.current_filter = current_filter

    def compose(self):
        with Container(id="filter-dialog"):
            yield Static("ADVANCED FILTER", id="filter-title")
            yield Input(
                value=self.current_filter,
                placeholder="ip 10.0.0.0/24 and port 445",
                id="filter-input"
            )
            yield Static(self._get_quick_help(), id="filter-help")

            with Horizontal(id="filter-presets"):
                for name in ["compromised", "hvt", "lateral", "creds"]:
                    yield Button(name, id=f"preset-{name}", classes="preset-btn")

            with Horizontal(id="filter-buttons"):
                yield Button("Apply", variant="primary", id="apply-btn")
                yield Button("Clear", variant="warning", id="clear-btn")
                yield Button("Cancel", variant="default", id="cancel-btn")

    def _get_quick_help(self) -> str:
        return """[dim]Quick Reference:
  ip 10.0.0.1       - Match IP
  codename SHADOW*  - Match codename
  port 445,3389     - Match ports
  proto smb         - Match protocol
  compromised       - Compromised only
  hvt               - High-value targets
  creds > 0         - Hosts with creds

Operators: and, or, not[/]"""

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "apply-btn":
            self._apply_filter()
        elif event.button.id == "clear-btn":
            self.query_one("#filter-input", Input).value = ""
        elif event.button.id == "cancel-btn":
            self.app.pop_screen()
        elif event.button.id.startswith("preset-"):
            preset_name = event.button.id[7:]
            if preset_name in FILTER_PRESETS:
                self.query_one("#filter-input", Input).value = FILTER_PRESETS[preset_name]

    def action_apply(self):
        self._apply_filter()

    def action_cancel(self):
        self.app.pop_screen()

    def _apply_filter(self):
        filter_text = self.query_one("#filter-input", Input).value
        self.post_message(self.FilterApplied(filter_text))
        self.app.pop_screen()


# ===================
# Session Recovery Screen
# ===================

class SessionRecoveryScreen(ModalScreen):
    """Modal screen for recovering previous sessions."""

    CSS = """
    SessionRecoveryScreen {
        align: center middle;
    }

    #session-dialog {
        width: 90;
        height: 25;
        border: tall #7ee787;
        background: #0d1117;
        padding: 1 2;
    }

    #session-title {
        text-align: center;
        text-style: bold;
        color: #7ee787;
        margin-bottom: 1;
    }

    #session-list {
        height: 15;
        overflow-y: auto;
        border: solid #30363d;
    }

    .session-item {
        padding: 0 1;
    }

    .session-item:hover {
        background: #21262d;
    }

    #session-buttons {
        margin-top: 1;
        align: center middle;
    }
    """

    class SessionSelected(Message):
        """Session selected for recovery."""
        def __init__(self, session_path: str):
            self.session_path = session_path
            super().__init__()

    def __init__(self, sessions: List[Dict]):
        super().__init__()
        self.sessions = sessions

    def compose(self):
        with Container(id="session-dialog"):
            yield Static("RECOVER SESSION", id="session-title")
            with Container(id="session-list"):
                for i, session in enumerate(self.sessions[:10]):
                    name = session.get("filename", "unknown")
                    updated = session.get("updated_at", "?")[:19]
                    source = session.get("source_name", "?")[:20]
                    hosts = session.get("host_count", 0)
                    creds = session.get("credential_count", 0)

                    yield Button(
                        f"{name[:30]:<30} {updated} {source} H:{hosts} C:{creds}",
                        id=f"session-{i}",
                        classes="session-item"
                    )

            with Horizontal(id="session-buttons"):
                yield Button("Cancel", variant="default", id="cancel-btn")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "cancel-btn":
            self.app.pop_screen()
        elif event.button.id.startswith("session-"):
            idx = int(event.button.id[8:])
            if idx < len(self.sessions):
                self.post_message(self.SessionSelected(self.sessions[idx]["path"]))
                self.app.pop_screen()


# ===================
# Session Mixin
# ===================

class SessionMixin:
    """
    Mixin for session persistence.

    Adds:
    - Auto-save every 30 seconds
    - Ctrl+S to save session
    - Ctrl+O to open/recover session
    - Session recovery on startup
    """

    # Additional bindings for session management
    SESSION_BINDINGS = [
        Binding("ctrl+s", "save_session", "Save", priority=True),
        Binding("ctrl+o", "open_session", "Open", priority=True),
    ]

    def init_session(self, encryption_key: Optional[str] = None):
        """Initialize session storage."""
        self._session_storage: Optional[SessionStorage] = None
        self._session_encryption_key = encryption_key
        self._auto_save_task: Optional[asyncio.Task] = None

    def start_session(self, source_type: str, source_name: str):
        """Start new session with auto-save."""
        self._session_storage = create_session_storage(
            source_type=source_type,
            source_name=source_name,
            encryption_key=self._session_encryption_key
        )

        # Start auto-save task
        if self._auto_save_task is None:
            self._auto_save_task = asyncio.create_task(self._auto_save_loop())

    async def _auto_save_loop(self):
        """Background auto-save loop."""
        while True:
            await asyncio.sleep(30)  # Every 30 seconds
            try:
                if self._session_storage and self._session_storage.should_auto_save():
                    self._save_session_data()
                    self._log_debug("Auto-saved session")
            except Exception as e:
                self._log_debug(f"Auto-save error: {e}")

    def _save_session_data(self):
        """Save current session state."""
        if not self._session_storage:
            return

        # Determine source type and name
        source_type = "pcap" if hasattr(self, 'pcap_file') and self.pcap_file else "interface"
        source_name = getattr(self, 'pcap_file', None) or getattr(self, 'interface', 'unknown')

        self._session_storage.save_all(
            source_type=source_type,
            source_name=source_name,
            packets=getattr(self, 'packets', 0),
            hosts=getattr(self, 'hosts', {}),
            flows=getattr(self, 'flows', {}),
            credentials=getattr(self, 'credentials', []),
            dns_resolutions=getattr(self, 'dns_resolutions', {}),
            alerts=getattr(self, 'alerts', []),
            compromised_hosts=getattr(self, 'compromised_hosts', set()),
            codenames=getattr(self, 'codenames', {})
        )

    def _load_session_data(self, session_path: str):
        """Load session from file."""
        try:
            storage = SessionStorage.load_session(
                db_path=session_path,
                encryption_key=self._session_encryption_key
            )
            data = storage.load_all()

            # Apply loaded data
            self.hosts = data.get("hosts", {})
            self.flows = data.get("flows", {})
            self.dns_resolutions = data.get("dns_resolutions", {})
            self.alerts = data.get("alerts", [])
            self.compromised_hosts = data.get("compromised_hosts", set())
            self.codenames = data.get("codenames", {})

            # Credentials need special handling (convert dicts back to objects)
            # For now, store as dicts - credential panel can handle both
            loaded_creds = data.get("credentials", [])
            # Note: Actual credential objects would need to be reconstructed

            # Refresh all tables
            if hasattr(self, '_refresh_all_tables'):
                self._refresh_all_tables()

            self._log_debug(f"Loaded session: {len(self.hosts)} hosts, {len(self.flows)} flows")
            storage.close()
            return True
        except Exception as e:
            self._log_debug(f"Session load error: {e}")
            return False

    def action_save_session(self):
        """Save current session."""
        if not self._session_storage:
            source_type = "pcap" if hasattr(self, 'pcap_file') and self.pcap_file else "interface"
            source_name = getattr(self, 'pcap_file', None) or getattr(self, 'interface', 'unknown')
            self.start_session(source_type, source_name)

        self._save_session_data()
        self._log_debug(f"Session saved to {self._session_storage.db_path}")

    def action_open_session(self):
        """Open session recovery dialog."""
        sessions = SessionStorage.list_sessions()
        if sessions:
            self.push_screen(SessionRecoveryScreen(sessions))
        else:
            self._log_debug("No previous sessions found")

    def on_session_recovery_screen_session_selected(self, message: SessionRecoveryScreen.SessionSelected):
        """Handle session selection."""
        self._load_session_data(message.session_path)


# ===================
# Filter Mixin
# ===================

class FilterMixin:
    """
    Mixin for advanced filtering.

    Adds:
    - / key opens advanced filter dialog
    - Filter bar in status area
    - BPF-style filter syntax
    """

    # Additional bindings for filtering
    FILTER_BINDINGS = [
        Binding("/", "advanced_filter", "Filter", priority=True),
        Binding("ctrl+f", "advanced_filter", "Filter", priority=True),
    ]

    def init_filter(self):
        """Initialize advanced filter."""
        self._advanced_filter = AdvancedFilter(
            codename_resolver=lambda ip: self._get_codename(ip)
        )

    def action_advanced_filter(self):
        """Open advanced filter dialog."""
        current = self._advanced_filter.filter_text if self._advanced_filter.is_active else ""
        self.push_screen(FilterInputScreen(current))

    def on_filter_input_screen_filter_applied(self, message: FilterInputScreen.FilterApplied):
        """Handle filter application."""
        if message.filter_text:
            if self._advanced_filter.parse(message.filter_text):
                self._log_debug(f"Filter applied: {message.filter_text}")
                self._refresh_filtered_tables()
            else:
                self._log_debug(f"Filter error: {self._advanced_filter.error}")
        else:
            self._advanced_filter.clear()
            self._log_debug("Filter cleared")
            self._refresh_filtered_tables()

    def _refresh_filtered_tables(self):
        """Refresh tables with filter applied."""
        # Update hosts table
        self._update_hosts_table_filtered()
        # Update flows table
        self._update_flows_table_filtered()
        # Update stats
        self._update_stats()

    def _update_hosts_table_filtered(self):
        """Update hosts table with advanced filter."""
        if not hasattr(self, '_advanced_filter') or not self._advanced_filter.is_active:
            # Fall back to standard update
            if hasattr(self, '_update_hosts_table'):
                self._update_hosts_table()
            return

        from ..streaming.tui import calculate_threat_score, get_hvt_icon, detect_high_value_target

        sorted_hosts = sorted(
            self.hosts.items(),
            key=lambda x: calculate_threat_score(x[1]),
            reverse=True
        )

        try:
            from textual.widgets import DataTable
            t = self.query_one("#hosts-table", DataTable)
            t.clear()
        except:
            return

        for ip, data in sorted_hosts[:50]:
            # Apply advanced filter
            if not self._advanced_filter.matches_host(
                ip, data, self.compromised_hosts, self.codenames, detect_high_value_target
            ):
                continue

            # Render row (same as original _update_hosts_table)
            codename, category, color = self._get_codename(ip)
            ports = data.get("services", set())
            ports_str = ",".join(str(s) for s in sorted(ports)[:5]) if ports else ""
            os_str = data.get("os", "?")[:12]
            cred_count = len(data.get("creds", []))
            score = calculate_threat_score(data)

            hvt_icon, _ = get_hvt_icon(ports)
            is_comp = ip in self.compromised_hosts

            # Build display (simplified)
            from rich.text import Text as RichText
            t.add_row(
                RichText(f"{hvt_icon or ''}{codename[:20]}", style=f"bold {color}"),
                ip,
                os_str,
                ports_str[:12],
                RichText(str(cred_count) if cred_count else "", style="bold red" if cred_count else "dim"),
                "",  # in_count
                "",  # out_count
                "",  # pivot_score
                "",  # age
                str(score),
            )

    def _update_flows_table_filtered(self):
        """Update flows table with advanced filter."""
        if not hasattr(self, '_advanced_filter') or not self._advanced_filter.is_active:
            if hasattr(self, '_update_flows_table'):
                self._update_flows_table()
            return

        sorted_flows = sorted(self.flows.items(), key=lambda x: x[1].get("count", 0), reverse=True)

        try:
            from textual.widgets import DataTable
            t = self.query_one("#flows-table", DataTable)
            t.clear()
        except:
            return

        for _, f in sorted_flows[:100]:
            if not self._advanced_filter.matches_flow(f, self.codenames):
                continue

            # Render row (simplified)
            src_cn, _, src_color = self._get_codename(f.get('src', ''))
            dst_cn, _, dst_color = self._get_codename(f.get('dst', ''))

            from rich.text import Text as RichText
            t.add_row(
                RichText("FLW", style="dim"),
                RichText(src_cn, style=src_color),
                RichText(dst_cn, style=dst_color),
                str(f.get('port', '')),
                f.get('proto', '')[:6],
                str(f.get('count', 0)),
                "",  # last_seen
            )


# ===================
# Timeline Mixin
# ===================

class TimelineMixin:
    """
    Mixin for behavioral timeline.

    Adds:
    - Timeline panel in layout
    - Real-time event streaming
    - Session detection
    - Behavioral pattern recognition
    """

    # Additional bindings for timeline
    TIMELINE_BINDINGS = [
        Binding("t", "toggle_timeline", "Timeline", priority=True),
    ]

    def init_timeline(self):
        """Initialize timeline panel."""
        self._timeline = TimelinePanel(
            codename_resolver=lambda ip: self._get_codename(ip),
            local_subnet=getattr(self, 'local_subnet', '10.0.0')
        )
        self._timeline_visible = False

    def _feed_flow_to_timeline(self, src: str, dst: str, port: int, proto: str = "TCP", count: int = 1):
        """Add flow to timeline."""
        if hasattr(self, '_timeline'):
            self._timeline.add_flow(src, dst, port, proto, count)

    def _feed_credential_to_timeline(self, cred):
        """Add credential to timeline."""
        if hasattr(self, '_timeline'):
            self._timeline.add_credential(
                protocol=cred.protocol,
                username=cred.username,
                domain=cred.domain,
                target_ip=cred.target_ip,
                target_port=cred.target_port
            )

    def _feed_alert_to_timeline(self, alert: Dict):
        """Add alert to timeline."""
        if hasattr(self, '_timeline'):
            self._timeline.add_alert(
                severity=alert.get("severity", "info"),
                alert_type=alert.get("type", "unknown"),
                message=alert.get("message", ""),
                src_ip=alert.get("src_ip", ""),
                dst_ip=alert.get("dst_ip", "") or alert.get("target", "")
            )

    def _feed_dns_to_timeline(self, domain: str, answers: List):
        """Add DNS to timeline."""
        if hasattr(self, '_timeline'):
            self._timeline.add_dns(domain, answers)

    def action_toggle_timeline(self):
        """Toggle timeline panel visibility."""
        self._timeline_visible = not self._timeline_visible

        try:
            timeline_pane = self.query_one("#timeline-pane", Container)
            if self._timeline_visible:
                timeline_pane.styles.display = "block"
                self._update_timeline_panel()
            else:
                timeline_pane.styles.display = "none"
        except:
            self._log_debug("Timeline pane not found in layout")

    def _update_timeline_panel(self):
        """Update timeline panel content."""
        if not self._timeline_visible:
            return

        try:
            content = self._timeline.render_compact(width=40, max_lines=15)
            self.query_one("#timeline-content", Static).update(content)
        except Exception as e:
            self._log_debug(f"Timeline update error: {e}")


# ===================
# Combined V2 Mixin
# ===================

class V2Features(SessionMixin, FilterMixin, TimelineMixin):
    """
    Combined v2.0 feature mixin.

    Includes all v2.0 features:
    - Session persistence
    - Advanced filtering
    - Behavioral timeline

    Apply this mixin to PcapIntelApp to enable all v2.0 features.
    """

    # Combined bindings
    V2_BINDINGS = (
        SessionMixin.SESSION_BINDINGS +
        FilterMixin.FILTER_BINDINGS +
        TimelineMixin.TIMELINE_BINDINGS
    )

    def init_v2_features(self, encryption_key: Optional[str] = None):
        """Initialize all v2.0 features."""
        self.init_session(encryption_key)
        self.init_filter()
        self.init_timeline()

    def _handle_flow_v2(self, entity):
        """Enhanced flow handler with timeline integration."""
        # Call original handler if exists
        if hasattr(super(), '_handle_flow'):
            super()._handle_flow(entity)

        # Feed to timeline
        from ..streaming.tui import get_entity_attr
        src = get_entity_attr(entity, "client_ip", "")
        dst = get_entity_attr(entity, "server_ip", "")
        port = get_entity_attr(entity, "service_port", 0)
        proto = get_entity_attr(entity, "protocol", "TCP")

        if src and dst:
            self._feed_flow_to_timeline(src, dst, port, proto)

    def _handle_credential_v2(self, cred):
        """Enhanced credential handler with timeline integration."""
        # Call original handler if exists
        if hasattr(super(), '_handle_credential'):
            super()._handle_credential(cred)

        # Feed to timeline
        self._feed_credential_to_timeline(cred)

        # Mark session dirty for auto-save
        if hasattr(self, '_session_storage') and self._session_storage:
            self._session_storage.mark_dirty()

    def _handle_alert_v2(self, alert):
        """Enhanced alert handler with timeline integration."""
        # Call original handler if exists
        if hasattr(super(), '_handle_alert'):
            super()._handle_alert(alert)

        # Feed to timeline
        self._feed_alert_to_timeline(alert)


# ===================
# Helper Functions
# ===================

def patch_tui_for_v2(app_class):
    """
    Decorator to patch TUI class with v2 features.

    Usage:
        @patch_tui_for_v2
        class PcapIntelApp(App):
            ...
    """
    # Add V2Features as parent class
    original_init = app_class.__init__

    def new_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self.init_v2_features(
            encryption_key=kwargs.get('encryption_key')
        )

    app_class.__init__ = new_init

    # Add v2 bindings
    if hasattr(app_class, 'BINDINGS'):
        app_class.BINDINGS = list(app_class.BINDINGS) + V2Features.V2_BINDINGS

    return app_class
