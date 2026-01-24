"""
Hosts Panel - Displays discovered hosts and their attributes.

Aggregates OS fingerprints, services, credentials, and flows per host.
"""

from typing import Any, Dict, List, Optional, Set

from rich.text import Text

from .base import Panel, PanelConfig


class HostsPanel(Panel):
    """
    Panel for displaying discovered hosts.

    Tracks per-host information including OS, services, credentials, and flows.
    """

    def __init__(self, config: PanelConfig, app=None):
        super().__init__(config, app)
        self._hosts: Dict[str, Dict] = {}  # ip -> host_data

    @classmethod
    def create_default(cls, app=None) -> "HostsPanel":
        """Create a hosts panel with default configuration."""
        config = PanelConfig(
            id="hosts",
            title="HOSTS",
            shortcut="4",
            color="#a371f7",
            priority=70,
            columns=["IP", "OS", "SVCS"],
        )
        return cls(config, app)

    def on_data_update(self, entity: Any) -> None:
        """
        Process a host-related entity event.

        Handles: os_fingerprint, service, host entities
        """
        etype = getattr(entity, "type", "")

        if etype == "os_fingerprint":
            self._handle_os_fingerprint(entity)
        elif etype == "service":
            self._handle_service(entity)
        elif etype == "host":
            self._handle_host(entity)
        else:
            # Try to extract IP and add as generic host
            ip = self._get_ip(entity)
            if ip:
                self._ensure_host(ip)

    def _get_attr(self, entity: Any, attr: str, default: Any = None) -> Any:
        """Safely get attribute from entity."""
        if hasattr(entity, "details") and isinstance(entity.details, dict):
            if attr in entity.details:
                return entity.details[attr]
        if hasattr(entity, "attributes") and isinstance(entity.attributes, dict):
            if attr in entity.attributes:
                return entity.attributes[attr]
        if hasattr(entity, attr):
            return getattr(entity, attr)
        return default

    def _get_ip(self, entity: Any) -> Optional[str]:
        """Extract IP from entity."""
        # Try common IP fields
        for field in ["ip", "src_ip", "dst_ip", "client_ip", "server_ip"]:
            ip = self._get_attr(entity, field)
            if ip:
                return str(ip)
        # Try value field
        val = getattr(entity, "value", "")
        if val and ":" in val:
            return val.rsplit(":", 1)[0]
        return None

    def _ensure_host(self, ip: str) -> Dict:
        """Ensure a host entry exists for this IP."""
        if ip not in self._hosts:
            self._hosts[ip] = {
                "os": "?",
                "services": set(),
                "creds": [],
                "flows": [],
                "dns": None,
                "mac": None,
            }
            self._data.append(ip)
        return self._hosts[ip]

    def _handle_os_fingerprint(self, entity: Any) -> None:
        """Handle OS fingerprint entity."""
        ip = self._get_attr(entity, "ip", "")
        if not ip:
            return

        os_info = getattr(entity, "value", "?")
        host = self._ensure_host(ip)
        host["os"] = os_info

        self.refresh_table()

    def _handle_service(self, entity: Any) -> None:
        """Handle service entity."""
        ip = self._get_attr(entity, "ip", "")
        port = self._get_attr(entity, "port", "")

        # Parse from value if needed
        val = getattr(entity, "value", "")
        if not ip and ":" in val:
            parts = val.rsplit(":", 1)
            ip = parts[0]
            port = parts[1]

        if ip and port:
            host = self._ensure_host(ip)
            try:
                host["services"].add(int(port))
            except (ValueError, TypeError):
                host["services"].add(str(port))

    def _handle_host(self, entity: Any) -> None:
        """Handle generic host entity."""
        ip = getattr(entity, "value", "")
        if not ip:
            return

        host = self._ensure_host(ip)

        # Copy any attributes
        if hasattr(entity, "attributes") and entity.attributes:
            for k, v in entity.attributes.items():
                if k not in host or host.get(k) in ("?", None):
                    host[k] = v

    def get_selected_item(self) -> Optional[tuple]:
        """Get the currently selected host."""
        idx = self.get_cursor_row()
        sorted_hosts = self._get_sorted_hosts()
        if idx is not None and idx < len(sorted_hosts):
            return sorted_hosts[idx]
        return None

    def _get_sorted_hosts(self) -> List[tuple]:
        """Get hosts sorted by activity."""
        return sorted(
            self._hosts.items(),
            key=lambda x: len(x[1].get("creds", [])) * 10 + len(x[1].get("flows", [])),
            reverse=True
        )

    def _render_rows(self, limit: int) -> None:
        """Render host rows to the table."""
        if not self._table:
            return

        self._table.clear()
        sorted_hosts = self._get_sorted_hosts()

        for ip, data in sorted_hosts[:limit]:
            svcs = data.get("services", set())
            svc_str = ",".join(str(s) for s in list(svcs)[:3])
            if len(svcs) > 3:
                svc_str += "..."

            os_str = data.get("os", "?")[:20]
            has_creds = bool(data.get("creds"))

            self._table.add_row(
                Text(ip[:15], style="bold #f85149" if has_creds else "#a371f7"),
                os_str,
                svc_str[:10],
            )

    @property
    def data_count(self) -> int:
        """Number of discovered hosts."""
        return len(self._hosts)

    def clear_data(self) -> None:
        """Clear all host data."""
        super().clear_data()
        self._hosts.clear()

    # ===== CORRELATION METHODS =====

    def add_credential(self, cred: Any) -> None:
        """Associate a credential with its target host."""
        target_ip = getattr(cred, "target_ip", None)
        if target_ip:
            host = self._ensure_host(target_ip)
            host["creds"].append(cred)
            port = getattr(cred, "target_port", None)
            if port:
                host["services"].add(int(port))

    def add_flow(self, flow_key: str, src: str, dst: str) -> None:
        """Associate a flow with the involved hosts."""
        for ip in [src, dst]:
            if ip and ip != "?":
                host = self._ensure_host(ip)
                if flow_key not in host["flows"]:
                    host["flows"].append(flow_key)

    def set_dns(self, ip: str, domain: str) -> None:
        """Associate a DNS name with a host."""
        host = self._ensure_host(ip)
        host["dns"] = domain

    def get_host(self, ip: str) -> Optional[Dict]:
        """Get host data for an IP."""
        return self._hosts.get(ip)

    def get_hosts_with_creds(self) -> List[tuple]:
        """Get hosts that have captured credentials."""
        return [(ip, data) for ip, data in self._hosts.items() if data.get("creds")]

    def get_hosts_by_os(self, os_pattern: str) -> List[str]:
        """Get hosts matching an OS pattern."""
        pattern = os_pattern.lower()
        return [ip for ip, data in self._hosts.items() if pattern in data.get("os", "").lower()]

    def get_hosts_with_service(self, port: int) -> List[str]:
        """Get hosts running a specific service port."""
        return [ip for ip, data in self._hosts.items() if port in data.get("services", set())]

    @classmethod
    def get_panel_css(cls) -> str:
        """Get CSS specific to the hosts panel."""
        return """
        #hosts-pane .pane-title {
            background: $secondary-darken-3;
        }

        #hosts-pane DataTable > .datatable--cursor {
            background: $secondary;
            color: white;
        }
        """
