"""
Alerts Panel - Displays security alerts and anomalies.

Shows credential captures, suspicious activity, and other security events.
"""

from typing import Any, Dict, List, Optional
from enum import Enum

from rich.text import Text

from .base import Panel, PanelConfig


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_STYLES = {
    AlertSeverity.CRITICAL: "bold white on red",
    AlertSeverity.HIGH: "bold #d29922",
    AlertSeverity.MEDIUM: "#d29922",
    AlertSeverity.LOW: "#8b949e",
    AlertSeverity.INFO: "dim",
}


class AlertsPanel(Panel):
    """
    Panel for displaying security alerts.

    Filters to show only significant alerts (MEDIUM and above by default).
    """

    def __init__(self, config: PanelConfig, app=None):
        super().__init__(config, app)
        self._min_severity = AlertSeverity.MEDIUM

    @classmethod
    def create_default(cls, app=None) -> "AlertsPanel":
        """Create an alerts panel with default configuration."""
        config = PanelConfig(
            id="alerts",
            title="ALERTS",
            shortcut="5",
            color="#d29922",
            priority=90,  # High priority - alerts are important
            columns=["SEV", "TYPE", "MESSAGE", "TARGET"],
        )
        return cls(config, app)

    def set_min_severity(self, severity: AlertSeverity) -> None:
        """Set minimum severity level to display."""
        self._min_severity = severity
        self.refresh_table()

    def on_data_update(self, alert: Dict) -> None:
        """
        Process an alert event.

        Args:
            alert: Alert dict with severity, type, message, etc.
        """
        sev_str = alert.get("severity", "info").upper()
        try:
            severity = AlertSeverity(sev_str.lower())
        except ValueError:
            severity = AlertSeverity.INFO

        # Filter by severity
        severity_order = list(AlertSeverity)
        if severity_order.index(severity) > severity_order.index(self._min_severity):
            return

        self._data.append(alert)

        # Update table
        if len(self._data) <= 100:
            self._add_table_row(alert)

    def get_selected_item(self) -> Optional[Dict]:
        """Get the currently selected alert."""
        idx = self.get_cursor_row()
        if idx is not None and idx < len(self._data):
            return self._data[idx]
        return None

    def _add_table_row(self, alert: Dict) -> None:
        """Add a single alert row to the table."""
        if not self._table:
            return

        sev_str = alert.get("severity", "info").upper()
        try:
            severity = AlertSeverity(sev_str.lower())
        except ValueError:
            severity = AlertSeverity.INFO

        style = SEVERITY_STYLES.get(severity, "dim")

        self._table.add_row(
            Text(sev_str[:4], style=style),
            alert.get("type", "")[:12],
            alert.get("message", "")[:40],
            alert.get("src_ip", alert.get("target", ""))[:15],
        )

    def _render_rows(self, limit: int) -> None:
        """Render alert rows to the table."""
        if not self._table:
            return

        self._table.clear()
        for alert in self._data[:limit]:
            self._add_table_row(alert)

    def get_by_severity(self, severity: AlertSeverity) -> List[Dict]:
        """Get alerts of a specific severity."""
        return [a for a in self._data if a.get("severity", "").lower() == severity.value]

    def get_by_type(self, alert_type: str) -> List[Dict]:
        """Get alerts of a specific type."""
        return [a for a in self._data if a.get("type", "") == alert_type]

    def get_by_target(self, target_ip: str) -> List[Dict]:
        """Get alerts involving a specific target."""
        return [
            a for a in self._data
            if target_ip in [a.get("src_ip"), a.get("dst_ip"), a.get("target"), a.get("ip")]
        ]

    def get_critical_alerts(self) -> List[Dict]:
        """Get only critical alerts."""
        return self.get_by_severity(AlertSeverity.CRITICAL)

    @classmethod
    def get_panel_css(cls) -> str:
        """Get CSS specific to the alerts panel."""
        return """
        #alerts-pane .pane-title {
            background: $warning-darken-3;
        }

        #alerts-pane DataTable > .datatable--cursor {
            background: $warning;
            color: black;
        }

        /* Severity-based row styling */
        #alerts-pane .severity-critical {
            background: $error;
            color: white;
        }

        #alerts-pane .severity-high {
            color: $warning;
        }
        """
