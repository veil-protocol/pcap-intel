"""
Credentials Panel - Displays captured authentication credentials.

Shows NTLM hashes, Kerberos tickets, HTTP auth, and other credentials
captured from network traffic.
"""

from typing import Any, Optional, List

from rich.text import Text

from .base import Panel, PanelConfig, PanelState


class CredentialsPanel(Panel):
    """
    Panel for displaying captured credentials.

    Data format expected:
        - protocol: str (ntlm, kerberos, http, etc.)
        - username: str
        - domain: str
        - target_ip: str
        - target_port: int
        - hashcat_format: Optional[str]
        - hashcat_mode: Optional[int]
    """

    @classmethod
    def create_default(cls, app=None) -> "CredentialsPanel":
        """Create a credentials panel with default configuration."""
        config = PanelConfig(
            id="creds",
            title="CREDENTIALS",
            shortcut="1",
            color="#f85149",
            priority=100,  # Highest priority - credentials are critical
            columns=["PROTO", "USER", "DOMAIN", "TARGET"],
        )
        return cls(config, app)

    def on_data_update(self, cred: Any) -> None:
        """
        Process a new credential event.

        Args:
            cred: Credential object with username, domain, protocol, etc.
        """
        # Create dedupe key from hash or user@domain
        dedupe_key = getattr(cred, "hashcat_format", None)
        if not dedupe_key:
            dedupe_key = f"{getattr(cred, 'username', '')}@{getattr(cred, 'domain', '')}"

        if not self.add_data(cred, dedupe_key):
            return  # Duplicate

        # Update table if not too many rows
        if len(self._data) <= 200:
            self._add_table_row(cred)

    def get_selected_item(self) -> Optional[Any]:
        """Get the currently selected credential."""
        idx = self.get_cursor_row()
        if idx is not None and idx < len(self._data):
            return self._data[idx]
        return None

    def _add_table_row(self, cred: Any) -> None:
        """Add a single credential row to the table."""
        if not self._table:
            return

        protocol = getattr(cred, "protocol", "?").upper()[:6]
        username = getattr(cred, "username", "?")[:15]
        domain = getattr(cred, "domain", "?")[:15]
        target_ip = getattr(cred, "target_ip", "?")
        target_port = getattr(cred, "target_port", "")
        target = f"{target_ip}:{target_port}" if target_ip else "?"

        self._table.add_row(
            Text(protocol, style="bold #f85149"),
            username,
            domain,
            target,
        )

    def _render_rows(self, limit: int) -> None:
        """Render credential rows to the table."""
        if not self._table:
            return

        self._table.clear()
        for cred in self._data[:limit]:
            self._add_table_row(cred)

    def get_hashcat_hashes(self) -> List[str]:
        """
        Get all hashcat-format hashes.

        Returns:
            List of hashcat-format strings
        """
        hashes = []
        for cred in self._data:
            hf = getattr(cred, "hashcat_format", None)
            if hf:
                hashes.append(hf)
        return hashes

    def get_by_target(self, target_ip: str) -> List[Any]:
        """
        Get all credentials for a specific target IP.

        Args:
            target_ip: Target IP address

        Returns:
            List of credentials targeting that IP
        """
        return [c for c in self._data if getattr(c, "target_ip", "") == target_ip]

    def get_by_user(self, username: str) -> List[Any]:
        """
        Get all credentials for a specific username.

        Args:
            username: Username to search for

        Returns:
            List of credentials with that username
        """
        return [c for c in self._data if getattr(c, "username", "") == username]

    @classmethod
    def get_panel_css(cls) -> str:
        """Get CSS specific to the credentials panel."""
        return """
        #creds-pane {
            border-right: solid $surface-darken-2;
        }

        #creds-pane .pane-title {
            background: $error-darken-3;
        }

        #creds-pane DataTable > .datatable--cursor {
            background: $error;
            color: white;
        }
        """
