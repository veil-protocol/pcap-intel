"""
Flows Panel - Displays network flow information.

Shows connections between hosts, ports, and connection counts.
"""

from typing import Any, Dict, Optional, List, Tuple

from rich.text import Text

from .base import Panel, PanelConfig


class FlowsPanel(Panel):
    """
    Panel for displaying network flows.

    Flows are aggregated by source:destination:port and counted.
    """

    def __init__(self, config: PanelConfig, app=None):
        super().__init__(config, app)
        self._flows: Dict[str, Dict] = {}  # flow_key -> flow_data

    @classmethod
    def create_default(cls, app=None) -> "FlowsPanel":
        """Create a flows panel with default configuration."""
        config = PanelConfig(
            id="flows",
            title="FLOWS",
            shortcut="2",
            color="#7ee787",
            priority=80,
            columns=["SRC -> DST", "PORT", "CNT"],
        )
        return cls(config, app)

    def on_data_update(self, entity: Any) -> None:
        """
        Process a flow entity event.

        Args:
            entity: Flow entity with client_ip, server_ip, service_port
        """
        # Extract flow details
        src = self._get_attr(entity, "client_ip", "?")
        dst = self._get_attr(entity, "server_ip", "?")
        port = self._get_attr(entity, "service_port", "?")
        proto = self._get_attr(entity, "protocol", "TCP")

        # Parse from value if details missing
        if src == "?" and hasattr(entity, "value"):
            val = entity.value
            if "->" in val:
                parts = val.split("->")
                src = parts[0]
                if ":" in parts[1]:
                    dst, port = parts[1].rsplit(":", 1)

        flow_key = f"{src}:{dst}:{port}"

        if flow_key in self._flows:
            self._flows[flow_key]["count"] += 1
        else:
            self._flows[flow_key] = {
                "src": src,
                "dst": dst,
                "port": port,
                "proto": proto,
                "count": 1,
            }
            # Add to base data for tracking
            self._data.append(flow_key)

        # Periodic table refresh
        if len(self._flows) <= 10 or len(self._flows) % 10 == 0:
            self.refresh_table()

    def _get_attr(self, entity: Any, attr: str, default: str = "") -> str:
        """Safely get attribute from entity."""
        # Try details dict first
        if hasattr(entity, "details") and isinstance(entity.details, dict):
            if attr in entity.details:
                return str(entity.details[attr])
        # Try attributes dict
        if hasattr(entity, "attributes") and isinstance(entity.attributes, dict):
            if attr in entity.attributes:
                return str(entity.attributes[attr])
        # Try direct attribute
        if hasattr(entity, attr):
            return str(getattr(entity, attr))
        return default

    def get_selected_item(self) -> Optional[Dict]:
        """Get the currently selected flow."""
        idx = self.get_cursor_row()
        sorted_flows = self._get_sorted_flows()
        if idx is not None and idx < len(sorted_flows):
            return sorted_flows[idx][1]
        return None

    def _get_sorted_flows(self) -> List[Tuple[str, Dict]]:
        """Get flows sorted by count (descending)."""
        return sorted(
            self._flows.items(),
            key=lambda x: x[1].get("count", 0),
            reverse=True
        )

    def _render_rows(self, limit: int) -> None:
        """Render flow rows to the table."""
        if not self._table:
            return

        self._table.clear()
        sorted_flows = self._get_sorted_flows()

        for _, flow in sorted_flows[:limit]:
            src = flow.get("src", "?")[:12]
            dst = flow.get("dst", "?")[:12]
            port = str(flow.get("port", "?"))
            count = str(flow.get("count", 0))

            self._table.add_row(
                f"{src}->{dst}",
                port,
                count,
            )

    @property
    def data_count(self) -> int:
        """Number of unique flows."""
        return len(self._flows)

    def clear_data(self) -> None:
        """Clear all flow data."""
        super().clear_data()
        self._flows.clear()

    def get_flows_for_ip(self, ip: str) -> List[Dict]:
        """
        Get all flows involving a specific IP.

        Args:
            ip: IP address to search for

        Returns:
            List of flows where IP is source or destination
        """
        return [
            flow for flow in self._flows.values()
            if flow.get("src") == ip or flow.get("dst") == ip
        ]

    def get_top_talkers(self, n: int = 10) -> List[Tuple[str, int]]:
        """
        Get the top N IP addresses by flow count.

        Args:
            n: Number of top talkers to return

        Returns:
            List of (ip, flow_count) tuples
        """
        ip_counts: Dict[str, int] = {}
        for flow in self._flows.values():
            for ip in [flow.get("src"), flow.get("dst")]:
                if ip and ip != "?":
                    ip_counts[ip] = ip_counts.get(ip, 0) + flow.get("count", 1)

        return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    @classmethod
    def get_panel_css(cls) -> str:
        """Get CSS specific to the flows panel."""
        return """
        #flows-pane .pane-title {
            background: $success-darken-3;
        }

        #flows-pane DataTable > .datatable--cursor {
            background: $success;
            color: white;
        }
        """
